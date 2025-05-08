'use client';

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export default function Login(){
  const router = useRouter();
  const [loginUrl, setLoginUrl] = useState("");

  const clientId = "";
  const tenantId = "";
  const redirectUri = 'http://localhost:3000/mslogin/redirect';
  const scope = 'openid profile email User.Read';

  // 토큰 만료시간 계산
  const checkExpireTime = (sec) => {
    const now = Date.now(); // 현재 시간 (ms 단위)
    const expiresIn = sec * 1000; // 응답에서 받은 값, 초 → 밀리초 변환
    const expiresAt = now + expiresIn; // 만료 예정 시간 계산
    console.log(now, expiresAt);
    return expiresAt;
  }

  // 토큰 디코딩
  const parseJwt = (token) => {
    try {
      const base64Url = token.split('.')[1]
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
      const jsonPayload = decodeURIComponent(
        atob(base64).split('').map(c =>
          '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
        ).join('')
      )
      return JSON.parse(jsonPayload)
    } catch (e) {
      console.error("❌ JWT 파싱 실패", e)
      return null
    }
  }

  // id token 디코딩해서 계정 정보 찾기
  const tokenUserInfo = (idToken) => {
    if (idToken) {
      const decoded = parseJwt(idToken);
      console.log('🧾 ID Token 디코드 결과:', decoded);
      console.log('user email : ', decoded.preferred_username);
      console.log('user name : ', decoded.name);

      const nonce = localStorage.getItem("auth_nonce")
      if (decoded?.nonce !== nonce) {
        console.error("⚠️ nonce 불일치. 리플레이 공격 가능성이 있습니다.")
        return
      }
      return decoded.preferred_username;
    }
    else {
      console.warn("ℹ️ 응답에 id_token이 포함되지 않았습니다.");
    }
  }

  useEffect(() => {
    console.log("📌 MS Login");
    
    // access token 재발급
    const refreshLogin = async () => {
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        const tokenRes = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: clientId,
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            scope,
            redirect_uri: redirectUri,
          }),
        });
        const result = await tokenRes.json();

        if (result.access_token) {
          console.log("🔓 재발급 성공 :", result);
          
          const expire_time = checkExpireTime(result.expires_in);
          localStorage.setItem("expire_time", expire_time);
          localStorage.setItem("access_token", result.access_token);
          
          const idToken = result.id_token;
          localStorage.setItem("id_token", idToken);
          const email = tokenUserInfo(idToken);

          return true;
        } else {
          console.log("❌ 재발급 실패 :", result);
          return false;
        }
      } else { 
        console.log("❌ 재발급 실패 : refreshToken 없음");
        return false;
      }
    };

    // 로그인
    const setupLogin = async () => {
      const codeVerifier = generateRandomString(128);
      const codeChallenge = await generateCodeChallenge(codeVerifier);
      localStorage.setItem("code_verifier", codeVerifier);

      // state & nonce 생성 및 저장 (권장)
      const state = crypto.randomUUID() // CSRF(Cross-Site Request Forgery, 사이트 간 요청 위조) 방지 목적
      const nonce = crypto.randomUUID() // ID 토큰 무결성 검증용 / 응답받은 token값 안에 nonce가 같이 들어 있음 / OpenID Connect 즉, OAuth 2.0을 기반한 로그인 인증 표준 프로토콜에 권장되는 리플레이 공격 방지 장치
      localStorage.setItem("auth_state", state)
      localStorage.setItem("auth_nonce", nonce)

      const authorizeUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize` +
        `?client_id=${encodeURIComponent(clientId)}` +
        `&response_type=code` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_mode=query` + // fragment(#) , query(?)
        // `&scope=${encodeURIComponent(scope)}` +
        `&scope=${encodeURIComponent('openid profile email offline_access')}` +
        `&code_challenge=${encodeURIComponent(codeChallenge)}` +
        `&code_challenge_method=S256` +
        `&state=${encodeURIComponent(state)}` +
        `&nonce=${encodeURIComponent(nonce)}`;
        // `&prompt=select_account` +
        // `&prompt=none`; // ✨ 로그인 상태 유지되었으면 자동 로그인

      setLoginUrl(authorizeUrl);
    };
  
    // 토큰 재발급 여부 파악
    const checkToken = async() => {
      const accessToken = localStorage.getItem('access_token');
      const now = Date.now();
      const expireTime = localStorage.getItem('expire_time');
      console.log(now, expireTime);

      if (expireTime == undefined || expireTime == null || !expireTime || !accessToken){ // 로그인 기록 없음
        console.log('💡 최초 로그인');
        setupLogin();
      } else if (now > expireTime - 5 * 60 * 1000) { // 만료 5분전 재발급
        console.log('💡 토큰 만료 or 토큰 만료 5분전 - 토큰 재발급 중..');
        const refreshresult = await refreshLogin(); // 재발급
        
        if(refreshresult){
          console.log('💡 토큰 재발급 성공');
          router.push("/");
        } else {
          console.log('💡 토큰 재발급 실패 - 재로그인 필요');
          setupLogin();
        }
      } else { // 만료시간 5분이상 남았을 경우 그대로 사용
        console.log('💡 토큰 만료 안됨 - 자동 로그인');
        const idToken = localStorage.getItem('id_token');
        const email = tokenUserInfo(idToken);

        router.push("/");
      }
    }

    checkToken();
}, []);

  return (
    <div style={{ padding: 50, textAlign: "center" }}>
      <h1>Microsoft 계정 로그인</h1>
      {loginUrl && (
        <a href={loginUrl}>
        <button style={{ padding: 10, fontSize: 16 }}>
          Microsoft 로그인
        </button>
      </a>
      )}
    </div>
  );
}

function generateRandomString(length){
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  let result = "";
  const values = new Uint32Array(length);
  window.crypto.getRandomValues(values);
  for (let i = 0; i < values.length; i++) {
    result += charset[values[i] % charset.length];
  }
  return result;
}

async function generateCodeChallenge(codeVerifier){
  const hashed = await sha256(codeVerifier);
  return base64UrlEncode(hashed);
}

function base64UrlEncode(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function sha256(plain) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hashBuffer);
}