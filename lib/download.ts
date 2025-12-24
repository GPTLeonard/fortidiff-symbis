export function downloadText(filename: string, text: string, mime = "text/plain;charset=utf-8") {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

export async function copyToClipboard(text: string) {
    if (!navigator?.clipboard) return;
    await navigator.clipboard.writeText(text);
}
