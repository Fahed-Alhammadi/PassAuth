/**
 * A stand-in for the browser's WebSocket (Node has a real one, which would go to the network). Installed as the
 * global `WebSocket` by test/chrome.ts `installChrome()`, with a fresh list of sockets each time. A test opens a
 * socket, sends it messages and drops it by hand; what the code sends is recorded.
 */
export class FakeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  /** Every socket made since the fake was installed, oldest first. */
  static all: FakeWebSocket[] = [];

  readyState = FakeWebSocket.CONNECTING;
  /** Text frames the code sent. */
  readonly sent: string[] = [];
  /** The code closed it (with this code). */
  closedWith: number | null = null;
  onopen: ((e: Event) => void) | null = null;
  onmessage: ((e: MessageEvent) => void) | null = null;
  onclose: ((e: CloseEvent) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;

  constructor(readonly url: string) {
    FakeWebSocket.all.push(this);
  }

  send(data: string) {
    if (this.readyState !== FakeWebSocket.OPEN) throw new Error("InvalidStateError: the socket isn't open");
    this.sent.push(data);
  }

  close(code = 1000) {
    if (this.readyState === FakeWebSocket.CLOSED) return;
    this.readyState = FakeWebSocket.CLOSED;
    this.closedWith = code;
  }

  // ----------------------------------------------------------- the test's side

  /** The server accepted the connection. */
  open() {
    this.readyState = FakeWebSocket.OPEN;
    this.onopen?.(new Event("open"));
  }

  /** A text frame from the server (objects are sent as JSON). */
  receive(data: unknown) {
    this.onmessage?.({ data: typeof data === "string" ? data : JSON.stringify(data) } as MessageEvent);
  }

  /** The connection broke (or the server closed it, with `code` and `reason`). */
  drop(code = 1006, reason = "") {
    this.readyState = FakeWebSocket.CLOSED;
    this.onerror?.(new Event("error"));
    this.onclose?.({ code, reason } as CloseEvent);
  }

  /** The sockets made since the fake was installed that are still open or opening. */
  static live(): FakeWebSocket[] {
    return FakeWebSocket.all.filter((s) => s.readyState === FakeWebSocket.OPEN || s.readyState === FakeWebSocket.CONNECTING);
  }
}
