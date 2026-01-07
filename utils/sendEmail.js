const SibApiV3Sdk = require("sib-api-v3-sdk");

const client = SibApiV3Sdk.ApiClient.instance;
client.authentications["api-key"].apiKey = process.env.BREVO_API_KEY;

const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();

async function sendEmail({ to, subject, html }) {
    return await apiInstance.sendTransacEmail({
        sender: {
            email: process.env.EMAIL_SENDER,
            name: "Aviation CET"
        },
        to: [{ email: to }],
        subject,
        htmlContent: html,
    });
}

module.exports = sendEmail;
