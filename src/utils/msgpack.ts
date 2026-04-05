import { Packr } from "msgpackr";

// useRecords:false emits standard msgpack (no nonstandard record extension).
// moreTypes:false keeps the extension set to what every other decoder understands.
// Packr.pack() returns Node Buffer, which Express sends with Content-Type:
// application/octet-stream (plain Uint8Array would be JSON-serialized).
export const msgpack = new Packr({ useRecords: false, moreTypes: false });
