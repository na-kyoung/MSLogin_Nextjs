'use client';

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";

export default function LoginRedirect(){
  const searchParams = useSearchParams();
  const router = useRouter();
  const [userInfo, setUserInfo] = useState(null);
  const [error, setError] = useState(null);
  
  const clientId = "";
  const tenantId = "";
  const redirectUri = 'http://localhost:3000/mslogin/redirect';
  
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
    console.log("📌 Login Redirect");

    const urlParams = new URLSearchParams(window.location.search.substring(1));
    const state = urlParams.get('state');
    const code = urlParams.get('code');
    
    const originalState = localStorage.getItem("auth_state");
    const codeVerifier = localStorage.getItem("code_verifier");

    if (!code) return console.error("❌ code가 없습니다.");
    if (!codeVerifier) return console.error("❌ PKCE code_verifier가 localStorage에 없습니다.");
    if(state !== originalState) return console.error("⚠️ state 불일치. CSRF 공격 가능성이 있습니다.")

    const fetchTokenAndUserInfo = async () => {
      try {
        const res = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            client_id: clientId,
            // client_secret: process.env.NEXT_PUBLIC_AZURE_AD_CLIENT_SECRET,
            // scope: "openid profile email",
            code,
            redirect_uri: redirectUri,
            grant_type: "authorization_code",
            code_verifier: codeVerifier, // 필수
          }),
        });

        const tokenData = await res.json();
        // console.log('토큰 정보 :', tokenData);
        // if(tokenData.error){ setError('Toekn Error :', tokenData.error_description); return }
        if (tokenData.access_token) {
          const expire_time = checkExpireTime(tokenData.expires_in);
          localStorage.setItem("expire_time", expire_time);
          localStorage.setItem("access_token", tokenData.access_token);
          localStorage.setItem("refresh_token", tokenData.refresh_token); // ⭐ 저장
          console.log("✅ 토큰 요청 완료 :", tokenData);
          // router.push("/"); // 로그인 성공 후 이동
        } else {
          console.error("❌ 토큰 요청 실패 :", tokenData);
        }

        const accessToken = tokenData.access_token;
        if(!accessToken) { console.log("accessToken 이 없습니다."); return }
        // console.log('accessToken :', accessToken);

        const idToken = tokenData.id_token;
        localStorage.setItem("id_token", idToken);
        tokenUserInfo(idToken);

        // const profileRes = await fetch("https://graph.microsoft.com/v1.0/me", {
        //   headers: {
        //     Authorization: `Bearer ${accessToken}`,
        //   },
        // });

        // const profileData = await profileRes.json();
        // console.log('👤 로그인 계정 정보 :', profileData);
        // if(profileData.error){ setError('profileData Error'); return }

        // setUserInfo(profileData);
        console.log('✅ 로그인 성공!');
      } catch (err) {
        setError("❌ 로그인 처리 중 오류 발생");
        console.error(err);
      }
    };

    fetchTokenAndUserInfo();
  }, []);


  // if (error) return <p>{error}</p>;
  // if (!userInfo) return <p>로그인 처리 중...</p>;

  return (
    <div style={{ padding: 50 }}>
      <h1>로그인 처리 화면</h1>
    </div>
  );
  
}