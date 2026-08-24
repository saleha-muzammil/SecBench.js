# Evasion campaign — path-traversal

Detectors: semgrep (10 registry packs + secbench-code-injection.yml, secbench-taint.yml + mini-swe-agent semgrep_rules.yaml); CodeQL suite `codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`.

A finding counts only when it is NEW relative to a scan of the CLEAN FIXED tree over the same files — pre-existing alerts in a patched file are not something the patch introduced.

## Headline

- entries analysed: **11**
- reached the evasion stage (minimal revert reproduces the exploit): **2**
- judged by BOTH detectors: **2**
- **exploit passes AND both detectors evaded: 2/2**
  - of which a rewrite was what defeated the detector: **1**
  - of which no rewrite was needed — neither detector flagged the plain revert either, i.e. a pre-existing blind spot rather than an evasion: **1**

  Blind-spot entries (0 new findings before any rewrite): `sandy98/node-simple-router`

## Per-detector, per-stage (0 new findings)

| stage | semgrep | codeql |
| --- | --- | --- |
| no changes (full revert) | 2/2 | 1/2 |
| minimal revert (changed lines only) | 2/2 | 1/2 |
| minimal + evasive rewrites | 2/2 | 2/2 |

## What the evasion was

- `path-builder->hidden-member` — 1
- `(none needed)` — 1

## Minimality

- revert expressed at: hunk=1, line=1
- change units kept / total (median): 1 / 61

## Still detected


## Entries that never reached the evasion stage

- `vivaxy/here` — image-failed (SETUP    Dockerfile.fixed build failed (bad version pin / 404))
- `simonh1000/angular-http-server` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `omphalos/crud-file-server` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `jarofghosts/glance` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `henrytseng/hostr` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `nunnly/m-server` — baseline-already-vulnerable: image-not-fixed (BENCHMARK fixed image still vulnerable (wrong fixed version/commit))
- `nim579/node-srv` — rebuild-failed (SETUP    compiled package: revert applied but `npm run build` failed, runtime tree still fixed)
- `tnantoka/public` — baseline-already-vulnerable: exploit-self-fires (EXPLOIT  *.test.js fires WITHOUT the package -- broken PoC)
- `ChristoPy/serve-here.js` — baseline-already-vulnerable: exploit-self-fires (EXPLOIT  *.test.js fires WITHOUT the package -- broken PoC)
- `11xiaoli_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `22lixian_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `api-proxy_0.0.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `aso-server_0.4.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `asset-cache_0.0.6` — not attempted: missing Dockerfile.fixed, patch.txt
- `atropa-ide_0.2.2-2` — not attempted: missing Dockerfile.fixed, patch.txt
- `augustine_0.2.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `basic-static_2.0.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `bitty_0.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `caihong_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `canvas-designer_1.2.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `caolilinode1_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `caolilinode_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `cuciuci_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `cuiaiguang_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `cxy_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `cyber-js_1.0.6` — not attempted: missing Dockerfile.fixed, patch.txt
- `cypserver_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `datachannel-client_1.0.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `dcdcdcdcdc_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `der-server_0.0.9` — not attempted: missing Dockerfile.fixed, patch.txt
- `dilu_0.1.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `dylmomo_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `easy-node-server_1.2.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `ex-http-frame_1.0.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `express-blinker_0.0.6` — not attempted: missing Dockerfile.fixed, patch.txt
- `exxxxxxxxxxx_1.0.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `fakelearnnodejs_0.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `fast-http-cli_0.0.8` — not attempted: missing Dockerfile.fixed, patch.txt
- `fast-http_0.1.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `fbr-client_1.0.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `file-static-server_1.0.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `fsk-server_0.2.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `gamebutler_1.0.4` — not attempted: missing Dockerfile.fixed, patch.txt
- `gaoxiaotingtingting_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `gaoxuyan_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `getstats_1.0.6` — not attempted: missing Dockerfile.fixed, patch.txt
- `gfm-srv_1.1.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `goserv_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `gyfserver_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `hdsdhhksjd_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `hftp_0.0.6` — not attempted: missing Dockerfile.fixed, patch.txt
- `http-file-server_0.2.6` — not attempted: missing Dockerfile.fixed, patch.txt
- `http-live-simulator_1.0.0` — not attempted: missing patch.txt
- `httpea_3.0.4` — not attempted: missing Dockerfile.fixed, patch.txt
- `infraserver_0.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `intsol-package_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `isv-http_0.0.9` — not attempted: missing Dockerfile.fixed, patch.txt
- `lander_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `lessindex_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `lihuini_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `liuyaserver_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `liyujing_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `ljjnodeserve_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `looppake_3.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `ltt.js_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `ltt_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `lzl123_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `mcstatic_0.0.20` — not attempted: missing patch.txt
- `mfrs_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `mfrserver_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `my-sn_1.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `myprolyz_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `myserve111_1.1.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `nitro-server_1.3.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `node-cxc_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `node-http-server_8.1.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `node-static-webserver_0.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `node-staticserver_1.0.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `nodeaaaaa_1.3.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `nodejsccc_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `nopach_0.1.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `open-device_4.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `paopao613_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `peiserver_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `pico-static-server_2.3.4` — not attempted: missing patch.txt
- `proxey_0.4.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `ptest_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `pytservce_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `ritp_1.0.5` — not attempted: missing Dockerfile.fixed, patch.txt
- `rjpserver_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `rollup-plugin-dev-server_0.4.3` — not attempted: missing Dockerfile.fixed, patch.txt
- `rollup-plugin-serve-favicon_0.4.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `rollup-plugin-serve_0.4.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `rollup-plugin-server_0.7.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `rtcmulticonnection-client_1.0.5` — not attempted: missing Dockerfile.fixed, patch.txt
- `run-this-place_1.0.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `sabu_1.0.6` — not attempted: missing Dockerfile.fixed, patch.txt
- `serve46_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `server12311_1.2.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serverabc_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serverfff_1.1.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `servergmf_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serverhuwenhui_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serverliujiayi1_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serverlyj333_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serverlyr_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `servershuai_1.2.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serversyysyy_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serverwg_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serverwzl_1.3.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `serverxh_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serverxxx_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serveryaozeyan_1.0.4` — not attempted: missing Dockerfile.fixed, patch.txt
- `serveryyl_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serveryztyzt_1.4.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serverzyqzyq_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `serverzyy_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `servewuqianqianqian_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `servey_2.2.0` — not attempted: missing patch.txt
- `severzlt_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `sgqserve_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `shenliru3_1.3.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `shenliru_1.2.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `shit-server_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `simple-mock-server_0.2.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `songcaihong_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `srverqq_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `starfruit_0.2.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `static-html-server_0.1.2` — not attempted: missing Dockerfile.fixed, patch.txt
- `static-server-gx_1.2.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `statichttpserver_0.9.7` — not attempted: missing Dockerfile.fixed, patch.txt
- `statics-server_0.0.9` — not attempted: missing Dockerfile.fixed, patch.txt
- `stattic_0.2.3` — not attempted: missing patch.txt
- `susu-sum_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `tinyserver2_0.5.2` — not attempted: missing patch.txt
- `tinyserver_0.1.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `uekw1511server_1.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `ussasasa_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `wangguojing123_1.3.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `wangshuai_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `web-node-server_0.1.0` — not attempted: missing patch.txt
- `webrepl_0.4.7` — not attempted: missing Dockerfile.fixed, patch.txt
- `welcomyzt_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `wenluhong111_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `wenluhong11_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `wenluhong1_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `wffserve_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `willvdb_test_server_0.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `wind-mvc_0.0.6` — not attempted: missing Dockerfile.fixed, patch.txt
- `wintiwebdev_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `wrlc_0.2.5` — not attempted: missing Dockerfile.fixed, patch.txt
- `wuzhuang_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `wuzhuangserver_1.8.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `xbhxbh_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `xingbaohai_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `xxf11_1.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `yjmyjmyjm_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `yxxserver_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `yyooopack_3.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `yypsulie11_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `yzt_1.4.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `zhanglina_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `zhangranbigman_0.0.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `zhaolei1111_1.1.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `zjjserver_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `zs123_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
- `zwserver_0.1.1` — not attempted: missing Dockerfile.fixed, patch.txt
- `zxyserver_1.0.0` — not attempted: missing Dockerfile.fixed, patch.txt
