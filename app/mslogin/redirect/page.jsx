'use client';

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { checkExpireTime, tokenUserInfo } from "@/app/lib/login";

export default function LoginRedirect(){
  const searchParams = useSearchParams();
  const router = useRouter();
  const [userInfo, setUserInfo] = useState(null);
  
  const clientId = "";
  const tenantId = "";
  const redirectUri = 'http://localhost:3000/mslogin/redirect';
  
  useEffect(() => {
    console.log("📌 Login Redirect");

    const urlParams = new URLSearchParams(window.location.search.substring(1));
    const state = urlParams.get('state');
    const code = urlParams.get('code');
    
    const originalState = localStorage.getItem("auth_state");
    const codeVerifier = localStorage.getItem("code_verifier");

    if (!code) { console.error("❌ code가 없습니다."); return; }
    if (!codeVerifier) { console.error("❌ code_verifier가 localStorage에 없습니다."); return; }
    if (state !== originalState) { console.error("⚠️ state 불일치. CSRF 공격 가능성이 있습니다."); return; }

    const fetchTokenAndUserInfo = async () => {
      try {
        const res = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            client_id: clientId,
            code,
            redirect_uri: redirectUri,
            grant_type: "authorization_code",
            code_verifier: codeVerifier, // 필수
            // client_secret: process.env.NEXT_PUBLIC_AZURE_AD_CLIENT_SECRET,
            // scope: "openid profile email",
          }),
        });

        const tokenData = await res.json();

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

        const idToken = tokenData.id_token;
        localStorage.setItem("id_token", idToken);
        const userEmail = tokenUserInfo(idToken);
        
        if(userEmail){
          setUserInfo(userEmail);
          console.log("userEmail :", userEmail);
          console.log('✅ 로그인 성공!');
        } else {
          console.error("id_token decoding error");
          return;
        }
      } catch (err) {
        console.error("❌ 로그인 처리 중 오류 발생", err);
      }
    };

    fetchTokenAndUserInfo();
  }, []);

  return (
    <>
      {userInfo ? (
        <div style={{ padding: 50 }}>
          <h1>{userInfo}</h1>
        </div>
      ):(
        <div style={{ padding: 50 }}>
          <h1>로그인 처리 중..</h1>
        </div>
      )}
    </>
  );
  
}