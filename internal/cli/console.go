package cli

import "os"

// console is the controlling terminal, used for prompts that must not go
// through redirected stdin or stdout.
type console struct{ in, out *os.File }

func (c *console) Write(p []byte) (int, error) { return c.out.Write(p) }

func (c *console) Close() error {
	c.in.Close()
	if c.out != c.in {
		c.out.Close()
	}
	return nil
}
