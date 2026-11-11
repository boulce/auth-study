package com.study.jwt.jwt;

/** 토큰 검증 실패. 메시지에 "왜" 거부됐는지 담는다 (학습용으로 응답 body에도 노출) */
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException(String message) {
        super(message);
    }
}
