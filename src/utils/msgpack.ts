import { Packr } from "msgpackr";

// Standard msgpack encoder/decoder configured for broad compatibility.
export const msgpack = new Packr({ moreTypes: false, useRecords: false });
