package server

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/txchen/yunmen/internal/files"
	"github.com/txchen/yunmen/internal/testutil"
)

func (c *client) putChunk(uploadID string, offset int64, b []byte) (int, map[string]any) {
	req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/uploads/%s?offset=%d", c.h.http.URL, uploadID, offset), bytes.NewReader(b))
	for k, v := range c.headers {
		req.Header[k] = v
	}
	req.Header.Set("X-Content-SHA256", digest(b))
	resp, err := (&http.Client{Jar: c.jar}).Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	jsonDecode(resp, &m)
	return resp.StatusCode, m
}

// upload sends data in chunkSize pieces and commits.
func (c *client) upload(hostID, dir, name string, data []byte, chunk int) (int, map[string]any) {
	st, begin := c.do("POST", "/api/v1/hosts/"+hostID+"/uploads", map[string]any{"directory": dir, "name": name, "size": len(data)})
	if st != 201 {
		return st, begin
	}
	id := begin["uploadId"].(string)
	for off := 0; off < len(data); off += chunk {
		end := min(off+chunk, len(data))
		if st, res := c.putChunk(id, int64(off), data[off:end]); st != 200 {
			return st, res
		}
	}
	return c.do("POST", "/api/v1/uploads/"+id+"/commit", map[string]string{})
}

func listNames(t *testing.T, dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestUploadDownloadAndListing(t *testing.T) {
	h, owner, id, tgt := sshdHost(t, ModeStandalone)
	dir := filepath.Join(tgt.Home, "dir with spaces 中文")
	os.Mkdir(dir, 0o755)
	os.WriteFile(filepath.Join(dir, ".hidden"), []byte("h"), 0o644)
	os.Symlink("/etc", filepath.Join(dir, "link"))

	data := make([]byte, 2*files.ChunkSize+1234)
	rand.Read(data)
	for name, content := range map[string][]byte{"big.bin": data, "empty": {}, "ünï code.txt": []byte("hi\r\n")} {
		if st, res := owner.upload(id, dir, name, content, files.ChunkSize); st != 200 {
			t.Fatalf("upload %s: %d %v", name, st, res)
		}
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("%s: stored content differs (%v)", name, err)
		}
		st, body := owner.raw("GET", "/api/v1/hosts/"+id+"/download?path="+url.QueryEscape(filepath.Join(dir, name)), nil)
		if st != 200 || !bytes.Equal(body, content) {
			t.Fatalf("download %s: %d, %d bytes", name, st, len(body))
		}
	}
	for _, n := range listNames(t, dir) {
		if strings.Contains(n, ".yunmen-") {
			t.Fatalf("temporary file left behind: %s", n)
		}
	}

	st, l := owner.do("GET", "/api/v1/hosts/"+id+"/files?path="+url.QueryEscape(dir), nil)
	if st != 200 {
		t.Fatalf("list: %d %v", st, l)
	}
	types := map[string]string{}
	for _, e := range l["entries"].([]any) {
		m := e.(map[string]any)
		types[m["name"].(string)] = fmt.Sprint(m["type"], "/", m["target"])
	}
	if types[".hidden"] != "file/<nil>" || types["link"] != "symlink/dir" || types["big.bin"] != "file/<nil>" {
		t.Fatalf("listing types: %v", types)
	}
	if st, _ := owner.do("GET", "/api/v1/hosts/"+id+"/files?path="+url.QueryEscape("/definitely/missing"), nil); st != 404 {
		t.Fatalf("missing dir: %d", st)
	}
	if st, _ := owner.raw("GET", "/api/v1/hosts/"+id+"/download?path="+url.QueryEscape(dir), nil); st != 400 {
		t.Fatalf("downloading a directory: %d", st)
	}

	cli, _ := h.pair(owner, StandalonePrincipal, "laptop")
	if st, _ := cli.do("GET", "/api/v1/hosts/"+id+"/files", nil); st != 401 {
		t.Fatalf("device token reached files API: %d", st)
	}
}

func TestUploadNeverOverwrites(t *testing.T) {
	_, owner, id, tgt := sshdHost(t, ModeStandalone)
	existing := filepath.Join(tgt.Home, "keep.txt")
	os.WriteFile(existing, []byte("original"), 0o644)
	if st, _ := owner.upload(id, tgt.Home, "keep.txt", []byte("replacement"), 4); st != 409 {
		t.Fatalf("upload over existing file at begin: %d", st)
	}

	// The destination appears while the upload is in progress.
	st, begin := owner.do("POST", "/api/v1/hosts/"+id+"/uploads", map[string]any{"directory": tgt.Home, "name": "race.txt", "size": 3})
	if st != 201 {
		t.Fatalf("begin: %d %v", st, begin)
	}
	upID := begin["uploadId"].(string)
	owner.putChunk(upID, 0, []byte("new"))
	os.WriteFile(filepath.Join(tgt.Home, "race.txt"), []byte("theirs"), 0o644)
	if st, _ := owner.do("POST", "/api/v1/uploads/"+upID+"/commit", map[string]string{}); st != 409 {
		t.Fatalf("commit over a file created mid-upload: %d", st)
	}
	if b, _ := os.ReadFile(filepath.Join(tgt.Home, "race.txt")); string(b) != "theirs" {
		t.Fatalf("existing file modified: %q", b)
	}
	if b, _ := os.ReadFile(existing); string(b) != "original" {
		t.Fatalf("existing file modified: %q", b)
	}

	// A dangling destination symlink is an existing entry, never followed.
	os.Symlink(filepath.Join(tgt.Home, "target-of-link"), filepath.Join(tgt.Home, "dangling"))
	if st, _ := owner.upload(id, tgt.Home, "dangling", []byte("x"), 1); st != 409 {
		t.Fatalf("upload onto dangling symlink: %d", st)
	}
	if _, err := os.Lstat(filepath.Join(tgt.Home, "target-of-link")); err == nil {
		t.Fatal("upload followed a destination symlink")
	}
	assertNoTemp(t, tgt.Home)
}

func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	for _, n := range listNames(t, dir) {
		if strings.Contains(n, ".yunmen-") {
			t.Fatalf("temporary file left behind: %s", n)
		}
	}
}

func TestUploadChunkRulesAndCancel(t *testing.T) {
	_, owner, id, tgt := sshdHost(t, ModeStandalone)
	st, begin := owner.do("POST", "/api/v1/hosts/"+id+"/uploads", map[string]any{"directory": tgt.Home, "name": "c.bin", "size": 6})
	if st != 201 {
		t.Fatalf("begin: %d", st)
	}
	upID := begin["uploadId"].(string)
	if st, res := owner.putChunk(upID, 0, []byte("abc")); st != 200 || res["confirmed"].(float64) != 3 {
		t.Fatalf("chunk 1: %d %v", st, res)
	}
	if st, res := owner.putChunk(upID, 0, []byte("abc")); st != 200 || res["confirmed"].(float64) != 3 {
		t.Fatalf("retried chunk not idempotent: %d %v", st, res)
	}
	if st, _ := owner.putChunk(upID, 5, []byte("f")); st != 409 {
		t.Fatalf("out-of-order chunk: %d", st)
	}
	if st, _ := owner.do("POST", "/api/v1/uploads/"+upID+"/commit", map[string]string{}); st != 400 {
		t.Fatalf("commit of incomplete upload: %d", st)
	}
	other := h2browser(owner)
	if st, _ := other.do("DELETE", "/api/v1/uploads/"+upID, nil); st != 410 {
		t.Fatalf("another session cancelled the upload: %d", st)
	}
	if st, _ := owner.do("DELETE", "/api/v1/uploads/"+upID, nil); st != 204 {
		t.Fatalf("cancel: %d", st)
	}
	if st, _ := owner.putChunk(upID, 3, []byte("def")); st != 410 {
		t.Fatalf("chunk after cancel: %d", st)
	}
	if _, err := os.Stat(filepath.Join(tgt.Home, "c.bin")); err == nil {
		t.Fatal("cancelled upload produced the final file")
	}
	assertNoTemp(t, tgt.Home)
}

func h2browser(c *client) *client {
	b := c.h.browser()
	b.login()
	return b
}

func TestSessionLogoutCancelsUploadAndCleansUp(t *testing.T) {
	h, owner, id, tgt := sshdHost(t, ModeStandalone)
	st, begin := owner.do("POST", "/api/v1/hosts/"+id+"/uploads", map[string]any{"directory": tgt.Home, "name": "x.bin", "size": 10})
	if st != 201 {
		t.Fatalf("begin: %d", st)
	}
	owner.putChunk(begin["uploadId"].(string), 0, []byte("12345"))
	owner.do("POST", "/api/v1/auth/logout", map[string]string{})
	waitCount(t, h, "")
	deadline := 50
	for ; deadline > 0 && hasTemp(t, tgt.Home); deadline-- {
		sleepMs(100)
	}
	assertNoTemp(t, tgt.Home)
}

func hasTemp(t *testing.T, dir string) bool {
	for _, n := range listNames(t, dir) {
		if strings.Contains(n, ".yunmen-") {
			return true
		}
	}
	return false
}

func TestSFTPUnavailableKeepsTerminal(t *testing.T) {
	tgt := testutil.GoServer(t, testutil.GoServerOptions{NoSFTP: true})
	h := newHarness(t, ModeStandalone)
	owner := h.browser()
	owner.login()
	_, probe := owner.do("POST", "/api/v1/hosts/probe", map[string]any{"address": tgt.Address, "port": tgt.Port})
	st, res := owner.do("POST", "/api/v1/hosts", map[string]any{"alias": "nosftp", "address": tgt.Address, "port": tgt.Port,
		"username": tgt.Username, "auth": passwordAuth(tgt), "observationId": probe["observationId"]})
	if st != 201 || res["sftpAvailable"] != false {
		t.Fatalf("create: %d %v", st, res)
	}
	id := res["host"].(map[string]any)["id"].(string)
	if st, _ := owner.do("GET", "/api/v1/hosts/"+id+"/files", nil); st != 501 {
		t.Fatalf("files on host without SFTP: %d", st)
	}
	tm := owner.openTerm(id)
	tm.send([]byte("echo ok-$((3*3))\r"))
	tm.expect("ok-9")
}

func TestUploadRefusedWithoutSafeNoReplace(t *testing.T) {
	if err := sftp.SetSFTPExtensions("posix-rename@openssh.com"); err != nil {
		t.Fatal(err)
	}
	defer sftp.SetSFTPExtensions("hardlink@openssh.com", "posix-rename@openssh.com", "statvfs@openssh.com")
	tgt := testutil.GoServer(t, testutil.GoServerOptions{})
	h := newHarness(t, ModeStandalone)
	owner := h.browser()
	owner.login()
	id := h.addHost(owner, "nolink", tgt, keyAuth(tgt))
	if st, res := owner.upload(id, tgt.Home, "f.txt", []byte("x"), 1); st != 501 {
		t.Fatalf("upload without hardlink support: %d %v", st, res)
	}
	assertNoTemp(t, tgt.Home)
}

func jsonDecode(resp *http.Response, v any) { json.NewDecoder(resp.Body).Decode(v) }

func sleepMs(n int) { time.Sleep(time.Duration(n) * time.Millisecond) }

// slowBody delivers its bytes in pieces with pauses, like a slow uplink.
type slowBody struct {
	data  []byte
	pause time.Duration
	fail  bool // return an error instead of EOF at the end
}

func (b *slowBody) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		if b.fail {
			return 0, io.ErrUnexpectedEOF
		}
		return 0, io.EOF
	}
	time.Sleep(b.pause)
	n := copy(p, b.data[:min(len(b.data), 4)])
	b.data = b.data[n:]
	return n, nil
}

func (c *client) putBody(uploadID string, offset int64, sum string, body io.Reader) int {
	req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/api/v1/uploads/%s?offset=%d", c.h.http.URL, uploadID, offset), body)
	for k, v := range c.headers {
		req.Header[k] = v
	}
	req.Header.Set("X-Content-SHA256", sum)
	resp, err := (&http.Client{Jar: c.jar}).Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestSlowChunkOutlastingIdleTimeoutSucceeds(t *testing.T) {
	h, owner, id, tgt := sshdHost(t, ModeStandalone)
	h.srv.files.UploadIdle = 400 * time.Millisecond
	data := []byte("0123456789abcdef")
	_, begin := owner.do("POST", "/api/v1/hosts/"+id+"/uploads", map[string]any{"directory": tgt.Home, "name": "slow.bin", "size": len(data)})
	upID := begin["uploadId"].(string)
	if st := owner.putBody(upID, 0, digest(data), &slowBody{data: data, pause: 250 * time.Millisecond}); st != 200 {
		t.Fatalf("slow chunk: %d", st)
	}
	if st, res := owner.do("POST", "/api/v1/uploads/"+upID+"/commit", map[string]string{}); st != 200 {
		t.Fatalf("commit after slow chunk: %d %v", st, res)
	}
	if got, _ := os.ReadFile(filepath.Join(tgt.Home, "slow.bin")); !bytes.Equal(got, data) {
		t.Fatalf("content %q", got)
	}
}

func TestInterruptedChunkCanBeResent(t *testing.T) {
	_, owner, id, tgt := sshdHost(t, ModeStandalone)
	data := []byte("abcdefghij")
	_, begin := owner.do("POST", "/api/v1/hosts/"+id+"/uploads", map[string]any{"directory": tgt.Home, "name": "r.bin", "size": len(data)})
	upID := begin["uploadId"].(string)
	owner.putBody(upID, 0, digest(data), &slowBody{data: data[:6], fail: true})
	if st, res := owner.putChunk(upID, 0, data); st != 200 || res["confirmed"].(float64) != 10 {
		t.Fatalf("resend after interruption: %d %v", st, res)
	}
	if st, _ := owner.do("POST", "/api/v1/uploads/"+upID+"/commit", map[string]string{}); st != 200 {
		t.Fatalf("commit: %d", st)
	}
	if got, _ := os.ReadFile(filepath.Join(tgt.Home, "r.bin")); !bytes.Equal(got, data) {
		t.Fatalf("content %q", got)
	}
}
