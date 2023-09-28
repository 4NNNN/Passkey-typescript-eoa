import React, { useState } from "react";
import {
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  platformAuthenticatorIsAvailable,
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
// @ts-ignore
import elliptic from "elliptic";
import base64url from "base64url";
import { v4 as uuidv4 } from "uuid";
import { AsnParser } from "@peculiar/asn1-schema";
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { utils } from "@passwordless-id/webauthn";
import * as cbor from "./utils/cbor";
import {
  arrayify,
  BytesLike,
  defaultAbiCoder,
  getCreate2Address,
  hexConcat,
  hexDataSlice,
  keccak256,
} from "ethers/lib/utils";
import {
  parseAuthData,
  publicKeyCredentialToJSON,
  shouldRemoveLeadingZero,
} from "./utils/helpers";
import TwoUserMultisig from "./utils/abi.json";
import UserOperation from "./utils/UserOperation";
import { ethers, BigNumber } from "ethers";
const EC = elliptic.ec;
const ec = new EC("p256");

export enum COSEKEYS {
  kty = 1,
  alg = 3,
  crv = -1,
  x = -2,
  y = -3,
  n = -1,
  e = -2,
}

const App: React.FC = () => {
  const [credentials, setCredentials] = useState<any>(null);
  const [publicKeys, setPublicKeys] = useState([] as any[]);
  const [signature, setSignature] = useState("");

  const createPassKey = async () => {
    const supportsWebAuthn = browserSupportsWebAuthn();
    const supportsWebAuthnAutofill = await browserSupportsWebAuthnAutofill();
    const platformAuthenticatorAvailable =
      await platformAuthenticatorIsAvailable();

    console.log(
      `Browser supports WebAuthn: ${supportsWebAuthn}
       Browser supports WebAuthn Autofill: ${supportsWebAuthnAutofill}
       Platform Authenticator available: ${platformAuthenticatorAvailable}`
    );

    const platform = platformAuthenticatorAvailable
      ? "platform"
      : "cross-platform";

    const username = "test";
    const challenge = uuidv4();
    // const challenge = "";
    const obj = {
      rp: {
        name: window.location.hostname,
        id: window.location.hostname,
      },
      user: {
        id: username,
        name: username,
        displayName: username,
      },
      challenge: challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      attestation: "direct",
      // timeout: 60000,
      authenticatorSelection: {
        userVerification: "required", // Webauthn default is "preferred"
        authenticatorAttachment: platform,
      },
    };
    console.log("registration options", obj);
    const publicKeyCredential = await startRegistration(obj as any);
    console.log(publicKeyCredential);

    const attestationObject = base64url.toBuffer(
      publicKeyCredential.response.attestationObject
    );
    const authData = cbor.decode(attestationObject.buffer, undefined, undefined)
      .authData as Uint8Array;

    let authDataParsed = parseAuthData(authData);

    let pubk = cbor.decode(
      authDataParsed.COSEPublicKey.buffer,
      undefined,
      undefined
    );

    const x = pubk[COSEKEYS.x];
    const y = pubk[COSEKEYS.y];

    const pk = ec.keyFromPublic({ x, y });

    const publicKey = [
      "0x" + pk.getPublic("hex").slice(2, 66),
      "0x" + pk.getPublic("hex").slice(-64),
    ];
    console.log({ publicKey });
    setCredentials(publicKeyCredential);
    setPublicKeys(publicKey);
  };

  const getMessageSignature = (authResponseSignature: string): BigNumber[] => {
    // See https://github.dev/MasterKale/SimpleWebAuthn/blob/master/packages/server/src/helpers/iso/isoCrypto/verifyEC2.ts
    // for extraction of the r and s bytes from the raw signature buffer
    const parsedSignature = AsnParser.parse(
      base64url.toBuffer(authResponseSignature),
      ECDSASigValue
    );
    let rBytes = new Uint8Array(parsedSignature.r);
    let sBytes = new Uint8Array(parsedSignature.s);
    if (shouldRemoveLeadingZero(rBytes)) {
      rBytes = rBytes.slice(1);
    }
    if (shouldRemoveLeadingZero(sBytes)) {
      sBytes = sBytes.slice(1);
    }
    // r and s values
    return [BigNumber.from(rBytes), BigNumber.from(sBytes)];
  };

  const signUserOperationHash = async (userOpHash: string) => {
    const challenge = utils
      .toBase64url(ethers.utils.arrayify(userOpHash))
      .replace(/=/g, "");
    console.log(challenge);
    const authData = await startAuthentication({
      rpId: window.location.hostname,
      challenge: challenge,
      userVerification: "required",
      // authenticatorType: "both",
      allowCredentials: [
        {
          type: "public-key",
          id: credentials.rawId,
        },
      ],
      // timeout: 60000,
    });
    const sign = getMessageSignature(authData.response.signature);
    console.log({ challenge, sign, authData });
    const clientDataJSON = new TextDecoder().decode(
      utils.parseBase64url(authData.response.clientDataJSON)
    );
    const challengePos = clientDataJSON.indexOf(challenge);
    const challengePrefix = clientDataJSON.substring(0, challengePos);
    const challengeSuffix = clientDataJSON.substring(
      challengePos + challenge.length
    );
    const authenticatorData = new Uint8Array(
      utils.parseBase64url(authData.response.authenticatorData)
    );
    const authd = utils.bufferToHex(authenticatorData)
    console.log(authd);
    const sig = {
      id: BigNumber.from(
        ethers.utils.keccak256(new TextEncoder().encode(credentials.id))
      ),
      r: sign[0],
      s: sign[1],
      authData: authenticatorData,
      clientDataPrefix: challengePrefix,
      clientDataSuffix: challengeSuffix,
    };
    console.log({ sig });
    let encodedSig = ethers.utils.defaultAbiCoder.encode(
      ["bytes32", "uint256", "uint256", "bytes", "string", "string"],
      [
        sig.id,
        sig.r,
        sig.s,
        sig.authData,
        sig.clientDataPrefix,
        sig.clientDataSuffix,
      ]
    );
    console.log({ encodedSig });
    return encodedSig;
  };

  function getUserOpHash(
    op: UserOperation,
    accountContract: string,
    chainId: number
  ): string {
    const userOpHash = keccak256(packUserOp(op,true));
    const enc = defaultAbiCoder.encode(
      ["bytes32", "address", "uint256"],
      [userOpHash, accountContract, chainId]
    );
    return keccak256(enc);
  }
  
  function packUserOp(op: UserOperation,forSignature = true): string {
    if (forSignature) {
      return defaultAbiCoder.encode(
        [
          "uint256",                    
          "uint256",
          "uint256",
          "uint256",
          "uint256",
          "uint256",
          "uint256",
          "uint256",
          "uint256",
          "uint256",
          "uint256[]",
          "bytes",
          "bytes32[]",
          "bytes",
          "bytes"
        ],
        [
          op.txType,
          op.from,
          op.to,
          op.gasLimit,
          op.gasPerPubdataByteLimit,
          op.maxFeePerGas,
          op.maxPriorityFeePerGas,
          op.paymaster,
          op.nonce,
          op.value,
          op.reserved,
          keccak256(op.data),
          op.factoryDeps,
          keccak256(op.paymasterInput),
          op.reservedDynamic
        ]
      );
      }else{
        return ("Invalid");
      }
  }

  const signUserOperation = async () => {
    const zksyncentryPointAddress = "0x23a1628c4d258D9fd5dFBA58B71a92157683a1c9"; //changed it to zksync abi as well as contract address
    //const sig = verifyPassKey()
    const userOp = {
      txType: "113",// Assuming Type.uint256 is a string type
      from: "0xcE89201ca3E036A324bBe7b4eD509430a6Ac39cf",
      to: "0x23a1628c4d258D9fd5dFBA58B71a92157683a1c9",
      gasLimit: "200000000",
      gasPerPubdataByteLimit: "50000000",
      maxFeePerGas: "50000000",
      maxPriorityFeePerGas: "50000000",
      paymaster: "0",
      nonce: "0",
      value: "0",
      reserved: ["0","0","0","0"],
      data: "0x977d08c00000000000000000000000000000000000000000000000000000000000000060fbf44f8e2d9d446231d2ee0ac7819c66f7a1c360630ead395c33ddce7d09553b05ad53a14271446919a317847f59f8ef322411c95d504467bdaa12ea95344c1d00000000000000000000000000000000000000000000000000000000000000057465737431000000000000000000000000000000000000000000000000000000",
      signature:"0x",
      factoryDeps: [], // Assuming Type.bytes32[] is an array of strings
      paymasterInput: "0x",
      reservedDynamic: "0x"
    };
    // const provider = new ethers.providers.JsonRpcProvider(
    //   "https://mainnet.infura.io/v3/8af40d61a66047ca8294a0bb43b958fa"
    // );
    // const entryPoint = new ethers.Contract(
    //   zksyncentryPointAddress,
    //   TwoUserMultisig.abi,
    //   provider
    // );
    const userOpHash = getUserOpHash(userOp,zksyncentryPointAddress,280);
    const signature = await signUserOperationHash(userOpHash);
    console.log({ userOpHash, signature });
    setSignature(signature);
    verifyPassKey();
    return signature;
  };

  const verifyPassKey = async () => {
    const challenge = "";
    const response = await startAuthentication({
      rpId: window.location.hostname,
      challenge: challenge,
      allowCredentials: [
        {
          type: "public-key",
          id: credentials.rawId,
        },
      ],
      // timeout: 60000,
    });
    console.log(response);
    const publicKeyCredentialParsed = publicKeyCredentialToJSON(response);

    const parsedSignature = AsnParser.parse(
      base64url.toBuffer(publicKeyCredentialParsed.response.signature),
      ECDSASigValue
    );

    let rBytes = new Uint8Array(parsedSignature.r);
    let sBytes = new Uint8Array(parsedSignature.s);

    if (shouldRemoveLeadingZero(rBytes)) {
      rBytes = rBytes.slice(1);
    }

    if (shouldRemoveLeadingZero(sBytes)) {
      sBytes = sBytes.slice(1);
    }

    const signatureverify = [
      "0x" + Buffer.from(rBytes).toString("hex"),
      "0x" + Buffer.from(sBytes).toString("hex"),
    ];
    console.log({ signatureverify });
  };

  return (
    <div>
      <main>
        <h2> Passkeys 256r1 signature test</h2>
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 15,
            maxWidth: 200,
            margin: "0 auto",
          }}
        >
          <button onClick={createPassKey}>Create Passkey</button>
          <button onClick={signUserOperation}>Verify Passkey</button>
        </div>

        {publicKeys.length > 0 && (
          <>
            <h4>Public key generated</h4>
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: 15,
                margin: "0 auto",
              }}
            >
              <li>{publicKeys[0]}</li>
              <li>{publicKeys[1]}</li>
            </div>
          </>
        )}

        {signature && (
          <p
            style={{
              margin: "0 auto",
              marginTop: 30,
              maxWidth: 600,
              wordBreak: "break-all",
            }}
          >
            UserOpSignature: <span style={{ color: "green" }}>{signature}</span>
          </p>
        )}
      </main>
    </div>
  );
};

export default App;
