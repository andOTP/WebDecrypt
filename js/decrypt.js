/* Copyright (C) 2019-2020 Jakob Nixdorf

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

var password;
var iterations, salt, iv;
var payload;

var decrypted_content;

let int_length = 4;
let salt_length = 12;
let iv_length = 12;

function openFile(event) {
    var input = event.target;

    var reader = new FileReader();
    reader.onload = function() {
        var arrayBuffer = reader.result;
        
        var iterBuffer = arrayBuffer.slice(0, int_length);
        // Javas ByteBuffer is Big Endian by default,
        // we need to consider this
        iterations = new DataView(iterBuffer).getInt32(false);

        salt = arrayBuffer.slice(int_length, int_length + salt_length);
        iv = arrayBuffer.slice(int_length + salt_length, int_length + salt_length + iv_length);
        payload = arrayBuffer.slice(int_length + salt_length + iv_length);

        document.getElementById("iptPassword").disabled = false;
        document.getElementById("btnDecrypt").disabled = false;
    };
    reader.readAsArrayBuffer(input.files[0]);
};

async function decrypt() {
    var pw = document.getElementById("iptPassword");
    password = pw.value;

    let keyMaterial = await getKeyMaterial();
    let key = await window.crypto.subtle.deriveKey(
        {
            "name": "PBKDF2",
            salt: salt,
            "iterations": iterations,
            "hash": "SHA-1"
        },
        keyMaterial,
        { "name": "AES-GCM", "length": 256 },
        false,
        [ "decrypt" ]
    );

    var decryptSuccess = true;

    let decrypted = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        payload
    )
    .catch(function(err) {
        console.error(err);
        decryptSuccess = false;
    })

    if (decryptSuccess) {
        decrypted_content = new TextDecoder("utf-8").decode(new Uint8Array(decrypted));

        document.getElementById("content").innerText = decrypted_content;
        document.getElementById("btnDownload").disabled = false;
        document.getElementById("btnShow").disabled = false;
    } else {
        decrypted_content = ""

        document.getElementById("content").innerText = ""
        document.getElementById("btnDownload").disabled = true;
        document.getElementById("btnShow").disabled = true;

        window.alert("Decryption failed, please check your password!");
    }
};

function toggleContent() {
    let contentDiv = document.getElementById("content");

    if (contentDiv.style.display === "none") {
        contentDiv.style.display = "block";
    } else if (contentDiv.style.display === "block") {
        contentDiv.style.display = "none";
    }
}


function downloadPlain() {
    data_uri = "data:text/json;charset=utf-8," + encodeURIComponent(decrypted_content);

    var element = document.createElement("a");
    element.setAttribute("href", data_uri);
    element.setAttribute("download", "andOTP_Backup.json");

    element.style.display = "none";

    document.body.appendChild(element);

    element.click();

    document.body.removeChild(element);
}

function getKeyMaterial() {
    let enc = new TextEncoder();

    return window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        [ "deriveBits", "deriveKey" ]
    );
}

function loadHandler() {
    document.getElementById("content").innerText = "";
    document.getElementById("content").style.display = "none";
    document.getElementById("iptFile").value = "";
    document.getElementById("iptPassword").disabled = true;
    document.getElementById("btnDecrypt").disabled = true;
    document.getElementById("btnDownload").disabled = true;
    document.getElementById("btnShow").disabled = true;
}

