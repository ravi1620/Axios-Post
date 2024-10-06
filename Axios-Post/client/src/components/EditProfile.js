import { useEffect, useRef, useState } from "react";
import React from "react";
import TopNavigation from "./TopNavigation";
import { useSelector } from "react-redux";

function EditProfile() {
  let firstNameInputRef = useRef();
  let lastNameInputRef = useRef();
  let emailInputRef = useRef();
  let passwordInputRef = useRef();
  let mobileInputRef = useRef();
  let profilePicInputRef = useRef();

let [profilePic, setprofilePic] = useState("/images/images.png");

let storeObj = useSelector((store)=>{ return store.loginReducer});

useEffect(()=>{
  if (storeObj.loginDetails) {
    firstNameInputRef.current.value = storeObj.loginDetails.firstName;
    lastNameInputRef.current.value = storeObj.loginDetails.lastName;
    emailInputRef.current.value = storeObj.loginDetails.email;
   mobileInputRef.current.value = storeObj.loginDetails.mobile;
    setprofilePic(`http://localhost:9876/${storeObj.loginDetails.profilePic}`);
  }
}, []);


  let updateProfile = async () => {
    let sendData = new FormData();

    sendData.append("firstName", firstNameInputRef.current.value);
    sendData.append("lastName", lastNameInputRef.current.value);
    sendData.append("email", emailInputRef.current.value);
    sendData.append("password", passwordInputRef.current.value);
     sendData.append("mobile", mobileInputRef.current.value);

    for (let i = 0; i < profilePicInputRef.current.files.length; i++) {
      sendData.append("profilePic", profilePicInputRef.current.files[i]);
    }

    let reqeustOptions = {
      method: "PATCH",
      body: sendData,
    };

    let jsonData = await fetch("http://localhost:9876/update", reqeustOptions);
    let jsoData = await jsonData.json();

    console.log(jsoData);
    alert(jsoData.msg);
    console.log(sendData);
  };

  return (
    <div>
      <TopNavigation></TopNavigation>
      <form>
        <div>
          <label>FirstName</label>
          <input ref={firstNameInputRef}></input>
        </div>
        <div>
          <label>LastName</label>
          <input ref={lastNameInputRef}></input>
        </div>
        <div>
          <label>Email</label>
          <input ref={emailInputRef} readOnly></input>
        </div>
        <div>
          <label>Password</label>
          <input ref={passwordInputRef}></input>
        </div>
        <div>
          <label>mobile</label>
          <input ref={mobileInputRef}></input>
        </div>
        <div>
          <label>ProfilePic</label>
          <input
            type="file"
            ref={profilePicInputRef}
            accept="image/*"
            onChange={(eo) => {
              let selectedImgPath = URL.createObjectURL(eo.target.files[0]);
              setprofilePic(selectedImgPath);
            }}
          ></input>
        </div>
        <img src={profilePic} alt="" className="img"></img>
        <div>
          <button
            type="button"
            onClick={() => {
              updateProfile();
            }}
          >
            update Profile
          </button>
        </div>
      </form>
    </div>
  );
}

export default EditProfile;
