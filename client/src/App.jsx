import React from 'react'
import { Routes, Route } from 'react-router-dom'
import Home from './pages/home'
import Login from './pages/login'
import ResetPassword from './pages/ResetPassword'
import EmailVerify from './pages/EmailVerify'
import { ToastContainer} from 'react-toastify';

const App = () => {
  return (
    <div>
      <ToastContainer />
      <Routes>
        <Route path="/" element={<Home/>} />
        <Route path="/login" element={<Login/>} />
        <Route path="/reset-password" element={<ResetPassword/>} />
        <Route path="/email-verify" element={<EmailVerify/>} />
      </Routes>
    </div>
    
  )
}

export default App
