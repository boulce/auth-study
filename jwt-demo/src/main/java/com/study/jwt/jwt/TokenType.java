package com.study.jwt.jwt;

/**
 * ACCESS: API 호출용. 짧게(15분) — 탈취돼도 피해 시간이 짧다.
 * REFRESH: Access 재발급 전용. 길게(14일) — 대신 서버 DB에 저장해서 폐기할 수 있게 한다.
 */
public enum TokenType {
    ACCESS, REFRESH
}
