"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../context/LoginContext";

export default function Login(){
  const {Loggedin, logout} = useAuth();
  const router = useRouter();

  return (
    <>
      <div>
        <button onClick={Loggedin ? logout : () => { router.push("/mslogin"); }} style={{ width:"80px", height:"30px", padding:"5px", border:"none", borderRadius:"5px", backgroundColor:"#c9c9c9", fontSize:"15px", cursor:"pointer" }}>
          {Loggedin ? 'Logout' : 'Login'}
        </button>
      </div>
    </>
  );
}