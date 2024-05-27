# Source Function

- websGetVar, getenv, nvram_get, get_cgi, httpGetEnv, find_var, cgiGetValue, nvram_safe_get, nvram_bufget, getvalue, apmib_get, acosNvramConfig_get, get_conf, webGetVarString

# Todo

[X] Custom 함수 RDA

[X] Pattern Matching(Bindiff)

[ ] 모든 Input(Source) Symbol 바이너리 찾기(Arm, Mips, etc..)

[ ] Strip된 바이너리에 전수 조사(약 20,000개) Linux 기본 파일시스템 바이너리 제외

[ ] json 형태로 저장

# Reference

- [Angr Bindiff](https://docs.angr.io/en/latest/_modules/angr/analyses/bindiff.html)
- [Bindiff Matching 알고리즘](https://github.com/google/bindiff/blob/main/docs/concepts.md)
