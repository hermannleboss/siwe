import cors from 'cors';
import express from 'express';
import {generateNonce, SiweMessage} from 'siwe';
import jwt from 'jsonwebtoken';


const app = express();
app.use(express.json());
app.use(cors({
    origin: 'http://localhost:8080',
    credentials: true,
}))

app.get('/nonce', async function (req, res) {

    res.setHeader('Content-Type', 'text/plain');
    res.send(generateNonce());
});
const secretKey = 'your-secret-key';
const sessionExpiry = '1h'; // Set the session expiry time to 1 hour.

app.post('/verify', async function (req, res) {
    const {message, signature} = req.body;
    const SIWEObject = new SiweMessage(message);


    try {
        const {data: newMessage} = await SIWEObject.verify({signature});
        // convert newMessage object into a  plain javascript object JSON
        const value = JSON.parse(JSON.stringify(newMessage));
        const token = jwt.sign(value, secretKey, {expiresIn: sessionExpiry});
        res.status(200).json({token});
    } catch (e) {
        console.log("Error: ", e)
        res.send(false);
    }
});

// verifiying the token
app.get('/personal_info', function (req, res) {
    const token = req.headers.authorization;
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            // Token is invalid
            return res.status(401).json({message: 'Token is invalid'});
        }

        // Token is valid, and `decoded` contains the payload data
        res.send(decoded);
    });
});


// app.get('/personal_information', function (req, res) {
//     if (!req.session.siwe) {
//         res.status(401).json({message: 'You have to first sign_in'});
//         return;
//     }
//     console.log("User is authenticated!");
//     res.setHeader('Content-Type', 'text/plain');
//     res.send(`You are authenticated and your address is: ${req.session.siwe.address}`);
// });

const port = parseInt(process.env.PORT) || 80;
app.listen(port, () => {
    console.log(`helloworld: listening on port ${port}`);
});