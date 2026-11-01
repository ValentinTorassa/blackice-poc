# Linux P0-06 run output, 2026-10-30 17:17 to 17:33 UTC

The complete receipt logs of the faults in [`../../P0-06-faults-linux.md`](../../P0-06-faults-linux.md), plus two
logs from the virtual machine's F3b run: the detached process's own output and the listener that took over the
dead proxy port. Files starting with `vm-` come from the disposable virtual machine; the others come from the host.

Only private IP address values were replaced: the host's direct-connection target with `TARGET_V4`, and the
virtual machine's gateway with `VM_GATEWAY_V4`. Rows, timestamps, ports, process IDs, scope IDs and every other
field are unchanged. Public addresses (registry.npmjs.org, example.com, httpbingo.org) are kept. The original logs
are retained privately; the hashes tell the raw originals from these copies (equal when nothing was replaced).

| File | Lines | Original SHA-256 | Published SHA-256 |
| --- | --- | --- | --- |
| `f1-proxy-stopped-receipts.jsonl` | 17 | `9744935c30b6ea6f4ddc4f9818ae3c7aead8fab23e371c11fd6b90e4995a7093` | `72638a7d92cca6f5ce1c39823eb3030ef0ee6e0b5031a3add61d3435793acd30` |
| `f2-kill-receipts.jsonl` | 5 | `b43813929fcfa14ca33510551c2627e7f2966a982f2e745200f5e82f75970ccf` | `258e3e54ed4a5e28e48da30efa028f5146524c042281ad6f91cc75b4cbb0a4dd` |
| `f2-term-receipts.jsonl` | 5 | `d32c0529d24616114b161a3f820280fbee2a40f0c021c37db95e8a810fbd0a4d` | `cb37dac7ce7e2d18c9669c0e86ed091a4123901f2d90d1826406abf7efa139d0` |
| `f2-ctrl-c-receipts.jsonl` | 5 | `cb28c55c1786a975a0e6e0ecbcc815d5ca4de7537aafe963c0734b1d53f5b089` | `0c678b373169a862d607b6b756d5e4c1f8894d9f7cc3e8fd04b5f285a5030e26` |
| `f3a-setup-failure-receipts.jsonl` | 4 | `9898f8757b3e22e80abfa27fc51c25a1020e69859798631968ef2adb3ebc0f07` | `9898f8757b3e22e80abfa27fc51c25a1020e69859798631968ef2adb3ebc0f07` |
| `f5-harness-error-receipts.jsonl` | 7 | `1786f00556f7243a651a54f9516d3133c2825789d2e58f9d6ff7de1ad011caff` | `1786f00556f7243a651a54f9516d3133c2825789d2e58f9d6ff7de1ad011caff` |
| `f5b-grant-expiry-receipts.jsonl` | 10 | `11f8af176c2fe9f61468a6ac2286f94788154f6b302e31d4a11661597d7d13c5` | `11f8af176c2fe9f61468a6ac2286f94788154f6b302e31d4a11661597d7d13c5` |
| `f6-new-scope-receipts.jsonl` | 5 | `881a112e0e85edb799cad5cc02a5e5be5cb4f8ce5e0e93aa451b112c2144b26c` | `881a112e0e85edb799cad5cc02a5e5be5cb4f8ce5e0e93aa451b112c2144b26c` |
| `workload-killed-receipts.jsonl` | 4 | `df99d7e144fc7a86bd709af4efeb001e8d91517cc04c147ce170567ee138ed9b` | `df99d7e144fc7a86bd709af4efeb001e8d91517cc04c147ce170567ee138ed9b` |
| `vm-f3b-helper-killed-receipts.jsonl` | 5 | `8032ea8696c64dc8d7994573d4d3adc8637d6a2c1864797278d2e254c9a1b9d5` | `8032ea8696c64dc8d7994573d4d3adc8637d6a2c1864797278d2e254c9a1b9d5` |
| `vm-f3b-second-run-receipts.jsonl` | 4 | `b95774320f4e67c161f8fe0a6ebabb7f215b96dd86d56a57bbceb5dad93c9cbd` | `b95774320f4e67c161f8fe0a6ebabb7f215b96dd86d56a57bbceb5dad93c9cbd` |
| `vm-f3b-survivor.log` | 12 | `f2c19ad4437683634ab12054d45f2f989771019ec0afe42c39d57021c0a7e7db` | `f2c19ad4437683634ab12054d45f2f989771019ec0afe42c39d57021c0a7e7db` |
| `vm-f3b-dead-port-listener.jsonl` | 3 | `01fb05793f7023c5ede0c8fdef7a6bc730a564bcf2e0d82b392cb6f9a37c0ae1` | `01fb05793f7023c5ede0c8fdef7a6bc730a564bcf2e0d82b392cb6f9a37c0ae1` |
| `vm-f4b-disk-full-receipts.jsonl` | 48 | `75b2df0b3c0295565c2de36dfac06544eefc5ee7b3516e03a29536d777c4913d` | `d42be444c1f45d81768d6f09653e6cb3dc8cbde7ce4c847139549ca7bf5f852b` |

The listener's `t` values are Unix seconds. 1793381405.04 is 17:30:05.04 UTC.
