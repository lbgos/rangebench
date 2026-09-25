// Render-stage module (on-disk copy / decoy).
//
// server.mjs resolves the stage through a one-shot data: URL built from this
// file's text. If this file's code executes for a request, the stage module
// was loaded the normal way (disk contents ran). When the loader is tricked
// into using an attacker-controlled `source`, this text never executes.
export const stage = 'render';
export default function mount() {
  return 'stage-mounted';
}
