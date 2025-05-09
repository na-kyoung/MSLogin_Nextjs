// id token 디코딩해서 계정 정보 찾기
export function tokenUserInfo(idToken) {
  if (idToken) {
    const decoded = parseJwt(idToken);
    console.log('🧾 ID Token 디코드 결과:', decoded);
    console.log('user email : ', decoded.preferred_username);
    console.log('user name : ', decoded.name);

    const nonce = localStorage.getItem("auth_nonce")
    if (decoded?.nonce !== nonce) {
      // console.error("idToken 디코딩 :", decoded?.nonce);
      // console.error("auth_nonce :", nonce);
      console.error("⚠️ nonce 불일치. 리플레이 공격 가능성이 있습니다.");
      return;
    }
    return decoded.preferred_username;
  }
  else {
    console.warn("ℹ️ 응답에 id_token이 포함되지 않았습니다.");
    return;
  }
}

// 토큰 디코딩
function parseJwt(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64).split('').map(c =>
        '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
      ).join('')
    );
    return JSON.parse(jsonPayload);
  } catch (e) {
    console.error("❌ JWT 파싱 실패", e);
    return null;
  }
}

// 토큰 만료시간 계산
export function checkExpireTime(sec) {
  const now = Date.now(); // 현재 시간 (ms 단위)
  const expiresIn = sec * 1000; // 응답에서 받은 값, 초 → 밀리초 변환
  const expiresAt = now + expiresIn; // 만료 예정 시간 계산
  console.log(now, expiresAt);
  return expiresAt;
}