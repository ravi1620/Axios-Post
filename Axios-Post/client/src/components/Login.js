import React, { useEffect, useRef } from "react";
import { useDispatch } from "react-redux";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";

function Login() {
  let emailInputRef = useRef();
  let passwordInputRef = useRef();
  let navigate = useNavigate();
  let action = useDispatch();
  axios.defaults.baseURL = "http://localhost:9876";
  axios.defaults.headers.common["Authorization"] = localStorage.token;

  useEffect(() => {
    if (localStorage.getItem("token")) {
      validateToken();
      axios.defaults.headers.common["Authorization"] =
        localStorage.getItem("token");
    }
  });

  let validateToken = async () => {
    let sendData = new FormData();

    sendData.append("token", localStorage.getItem("token"));

    axios.post("/validateToken");
    let requestOptions = {
      method: "POST",
      body: sendData,
    };

    let jsonData = await fetch(
      "http://localhost:9876/validateToken",
      requestOptions
    );

    let jsoData = await jsonData.json();
    console.log(jsoData);

    if (jsoData.status == "Success") {
      action({ type: "login", data: jsoData.data });
      // navigate("/dashboard");
    } else {
      alert(jsoData.msg);
    }
  };

  let onLogin = () => {
    return async () => {
      let sendData = new FormData();

      sendData.append("email", emailInputRef.current.value);
      sendData.append("password", passwordInputRef.current.value);

      let response = await axios.post("/Login", sendData);
      console.log(response);

      // console.log(jsoData.data);

      if (response.data.status == "Success") {
        localStorage.setItem("token", response.data.data.token);

        action({ type: "login", data: response.data.data });
        navigate("/dashboard");
      } else {
        alert(response.data.data.msg);
      }
    };
  };

  return (
    <div>
      <form>
        <h1>Login</h1>
        <div>
          <label>Email</label>
          <input ref={emailInputRef}></input>
        </div>
        <div>
          <label>Password</label>
          <input ref={passwordInputRef}></input>
        </div>
        <div>
          <button
            type="button"
            onClick={() => {
              action(onLogin());
            }}
          >
            Login
          </button>
        </div>
      </form>
      <br></br>
      <div className="div">
        <Link to="/signup" className="link">
          Signup
        </Link>
        <h2>Don't you have the account ? </h2>
      </div>
    </div>
  );
}

export default Login;
