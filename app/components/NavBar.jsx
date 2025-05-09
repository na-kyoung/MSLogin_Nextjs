"use client";

import { useRouter } from "next/navigation";
import Login from "./Login";

export default function NavBar(){
  const router = useRouter();

  function handleTitle(){
    router.push("/");
  }

  return (
    <div style={{ height:"40px", display:"flex", justifyContent:"space-between", alignItems:"center", paddingLeft:"10px", paddingRight:"10px", backgroundColor:"#e3e3e3", cursor:"pointer" }}>
      <div onClick={handleTitle}>
        <p style={{ fontSize:"28px", fontWeight:"bold" }}>DEMO</p>
      </div>
      <Login />
    </div>
  )
}