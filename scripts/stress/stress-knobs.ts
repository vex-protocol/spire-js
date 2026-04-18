/**
 * Live-adjustable load knobs (stdin +/− when TTY raw mode is enabled).
 */
export class StressKnobs {
    private readonly initial: number;
    private n: number;

    public constructor(initial: number) {
        this.initial = Math.max(1, Math.floor(initial));
        this.n = this.initial;
    }

    public get concurrency(): number {
        return this.n;
    }

    public up(step = 10): void {
        this.n = Math.min(50_000, this.n + Math.max(1, Math.floor(step)));
    }

    public down(step = 10): void {
        this.n = Math.max(1, this.n - Math.max(1, Math.floor(step)));
    }

    public reset(): void {
        this.n = this.initial;
    }

    public get initialConcurrency(): number {
        return this.initial;
    }
}
