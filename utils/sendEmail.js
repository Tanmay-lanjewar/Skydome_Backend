const axios = require("axios");

async function sendEmail({ to, subject, html }) {
    if (!process.env.BREVO_API_KEY) {
        throw new Error("BREVO_API_KEY is missing");
    }

    return axios.post(
        "https://api.brevo.com/v3/smtp/email",
        {
            sender: {
                email: process.env.EMAIL_SENDER,
                name: "Aviation CET",
            },
            to: [{ email: to }],
            subject,
            htmlContent: html,
        },
        {
            headers: {
                "api-key": process.env.BREVO_API_KEY,   // 🔑 EXPLICIT HEADER
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout: 10000,
        }
    );
}

module.exports = sendEmail;
