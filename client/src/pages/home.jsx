import React from 'react'
import Navber from '../components/Navber.jsx'
import Header from '../components/Header.jsx'

const home = () => {
  return (
    <div className='flex flex-col items-center justify-center min-h-screen bg-[url("/bg_img.png")] bg-cover bg-center'>
        <Navber/>
        <Header/>
    </div>
  )
}

export default home
