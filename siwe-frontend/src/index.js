import {BrowserProvider} from 'ethers';
import {SiweMessage} from 'siwe';

const domain = window.location.host;
const origin = window.location.origin;
const provider = new BrowserProvider(window.ethereum);

const profileElm = document.getElementById('profile');
const noProfileElm = document.getElementById('noProfile');
const welcomeElm = document.getElementById('welcome');

const ensLoaderElm = document.getElementById('ensLoader');
const ensContainerElm = document.getElementById('ensContainer');
const ensTableElm = document.getElementById('ensTable');

let address;

const BACKEND_ADDR = "https://siwe-backend-kvehw4df5q-uc.a.run.app";

async function createSiweMessage(address, statement) {
    const res = await fetch(`${BACKEND_ADDR}/nonce`, {
        credentials: 'include',
    });
    const message = new SiweMessage({
        domain,
        address,
        statement,
        uri: origin,
        version: '1',
        chainId: '1',
        nonce: await res.text()
    });
    return message.prepareMessage();
}

function connectWallet() {
    provider.send('eth_requestAccounts', [])
        .catch(() => console.log('user rejected request'));
}

async function signInWithEthereum() {
    const signer = await provider.getSigner();
    profileElm.classList = 'hidden';
    noProfileElm.classList = 'hidden';
    welcomeElm.classList = 'hidden';

    address = await signer.getAddress()
    const message = await createSiweMessage(
        address,
        'Sign in with Ethereum to the app.'
    );
    const signature = await signer.signMessage(message);
    console.log("message : '", message, "'")
    console.log("signature : '", signature, "'")

    const res = await fetch(`${BACKEND_ADDR}/verify`, {
        method: "POST",
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({message, signature}),
        credentials: 'include'
    });

    if (!res.ok) {
        console.error(`Failed in getInformation: ${res.statusText}`);
        return
    }
    const {token} = await res.json();
    const data = await fetch(`${BACKEND_ADDR}/personal_info`, {
        method: "GET",
        headers: {
            'Content-Type': 'application/json',
            'Authorization': token,
        }
    });

    console.log("response",await data.json());

    // displayENSProfile();
}

async function getInformation() {
    const res = await fetch(`${BACKEND_ADDR}/personal_information`, {
        credentials: 'include',
    });

    if (!res.ok) {
        console.error(`Failed in getInformation: ${res.statusText}`);
        return
    }

    let result = await res.text();
    console.log(result);
    address = result.split(" ")[result.split(" ").length - 1];
    displayENSProfile();
}

async function displayENSProfile() {
    const ensName = await provider.lookupAddress(address);

    if (ensName) {
        profileElm.classList = '';

        welcomeElm.innerHTML = `Hello, ${ensName}`;
        let avatar = await provider.getAvatar(ensName);
        if (avatar) {
            welcomeElm.innerHTML += ` <img class="avatar" src=${avatar}/>`;
        }

        ensLoaderElm.innerHTML = 'Loading...';
        ensTableElm.innerHTML.concat(`<tr><th>ENS Text Key</th><th>Value</th></tr>`);
        const resolver = await provider.getResolver(ensName);

        const keys = ["email", "url", "description", "com.twitter"];
        ensTableElm.innerHTML += `<tr><td>name:</td><td>${ensName}</td></tr>`;
        for (const key of keys)
            ensTableElm.innerHTML += `<tr><td>${key}:</td><td>${await resolver.getText(key)}</td></tr>`;
        ensLoaderElm.innerHTML = '';
        ensContainerElm.classList = '';
    } else {
        welcomeElm.innerHTML = `Hello, ${address}`;
        noProfileElm.classList = '';
    }

    welcomeElm.classList = '';
}

const connectWalletBtn = document.getElementById('connectWalletBtn');
const siweBtn = document.getElementById('siweBtn');
const infoBtn = document.getElementById('infoBtn');
connectWalletBtn.onclick = connectWallet;
siweBtn.onclick = signInWithEthereum;
infoBtn.onclick = getInformation;
