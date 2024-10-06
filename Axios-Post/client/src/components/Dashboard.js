import React from "react";
import { useDispatch, useSelector } from "react-redux";
import TopNavigation from "./TopNavigation";

function Dashboard() {
let action = useDispatch();
  let abc = async ()=>{
    let requestOptions = {
      method:"DELETE"
    }

    let url = `http://localhost:9876/deleteProfile?email=${storeObj.loginDetails.email}`
    let jsonData = await fetch(url,requestOptions);
    let jsoData = await jsonData.json();
    alert(jsoData.msg);
  }

  let storeObj = useSelector((store) => {
    console.log(store);
    return store.loginReducer;
  });
  return (
    <div>
      <TopNavigation></TopNavigation>
      <h1>Dashboard</h1>
      <div>
      <button type="button" onClick={()=>{
        abc();
      }}>Delete Account</button>
      </div>

      <button onClick={()=>{
action({type:"assignTask",data:"a"});
      }}>Assign Task</button>
            <button onClick={()=>{
action({type:"submitTask",data:"b"});
      }}>Submit Task</button>
            <button onClick={()=>{
action({type:"approveTask",data:"c"});
      }}>Approve Task</button>
            <button onClick={()=>{
action({type:"rejectTask",data:"d"});
      }}>Reject Task</button>

      <br></br>

      <button onClick={()=>{
action({type:"applyLeave",data:"ab"});
      }}>Apply Leave</button>
            <button onClick={()=>{
action({type:"submitLeave",data:"bc"});
      }}>Submit Leave</button>
            <button onClick={()=>{
action({type:"approveLeave",data:"cd"});
      }}>Approve Leave</button>
            <button onClick={()=>{
action({type:"rejectLeave",data:"de"});
      }}>Reject Leave</button>

      <h1>
        {storeObj.loginDetails.firstName} {storeObj.loginDetails.lastName}
      </h1>
      <img
        src={`http://localhost:9876/${storeObj.loginDetails.profilePic}`}
        className="img1"
      ></img>

    </div>
  );
}

export default Dashboard;
