export type DetectedDate = {
    iso: string | null;
    time: number | null;
    source: "content" | "filename" | null;
};

function parseIsoLike(y: string, m: string, d: string): Date | null {
    const year = Number(y);
    const month = Number(m);
    const day = Number(d);

    if (!Number.isFinite(year) || !Number.isFinite(month) || !Number.isFinite(day)) return null;
    if (month < 1 || month > 12) return null;
    if (day < 1 || day > 31) return null;

    const dt = new Date(Date.UTC(year, month - 1, day));
    if (Number.isNaN(dt.getTime())) return null;

    return dt;
}

function detectFromString(input: string): DetectedDate {
    // Matches YYYY-MM-DD, YYYY/MM/DD, YYYY.MM.DD
    // Lookahead/behind prevents matching inside longer numbers
    const re = /(?<!\d)(20\d{2})[-\/\.](0[1-9]|1[0-2])[-\/\.](0[1-9]|[12]\d|3[01])(?!\d)/g;

    let match: RegExpExecArray | null = null;
    let best: Date | null = null;

    while ((match = re.exec(input)) !== null) {
        const dt = parseIsoLike(match[1], match[2], match[3]);
        if (!dt) continue;
        if (!best || dt.getTime() > best.getTime()) best = dt;
    }

    if (!best) return { iso: null, time: null, source: null };

    const iso = best.toISOString().slice(0, 10);
    return { iso, time: best.getTime(), source: null };
}

export function detectConfigDate(text: string, filename: string): DetectedDate {
    const fromContent = detectFromString(text);
    if (fromContent.time) return { ...fromContent, source: "content" };

    const fromName = detectFromString(filename);
    if (fromName.time) return { ...fromName, source: "filename" };

    return { iso: null, time: null, source: null };
}
