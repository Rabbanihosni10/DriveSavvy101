import nodemailer from 'nodemailer';

const transporter= nodemailer.createTransport({
    host:"smtp-relay.brevo.com",
    PORT: 587,
    auth:{
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    }
})

export default transporter;