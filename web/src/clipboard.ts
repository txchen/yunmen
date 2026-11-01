export async function copyText(text: string): Promise<string> {
  try {
    await navigator.clipboard.writeText(text)
    return 'Copied.'
  } catch {
    return 'Copy failed. Select the text and copy it manually.'
  }
}
