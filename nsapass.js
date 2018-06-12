$(document).ready(function() {
    $("#inputPwd").keyup(function(event) {
        $("#resultCheckOk").hide();
        $("#resultCheckKo").hide();
        $("#resultGen").hide();
        strengthMeter("inputPwd");
    });
    strengthMeter("inputPwd");
});

$(function() {
  getMetaInf();
});


function getMetaInf(){
    $.getJSON("check.php?meta", function(response) {
		document.getElementById("metaInfo").innerHTML = "Database version : " + response.db_version + " - Entries : "+ response.nb_password+" - Requests counter : "+response.req_count;
    });
}

function checkPwd(lengthPwdGenerate) {
    // We transform the string into an arraybuffer.
    var str = document.getElementById("inputPwd").value;
    var buffer = new TextEncoder("utf-8").encode(str);
    return crypto.subtle.digest("SHA-1", buffer).then(function(hash) {
        var hexValue = hex(hash);
        checkInDb(hexValue, lengthPwdGenerate);
    });
}

function checkInDb(hashedPwd, lengthPwdGenerate) {
    var prefix = hashedPwd.substring(0, 5).toUpperCase();
    var suffix = hashedPwd.substring(5, hashedPwd.length).toUpperCase();

    $.get("check.php?password=" + prefix, function(response) {
        var splitted = response.split("\n");
        if (splitted.length == 0) {
		$("#resultCheckOk").show();
                $("#resultCheckKo").hide();
		return;
	}
        for (i = 0; i < splitted.length; i++) {
            var line = splitted[i].split(":");
            if (line[0] == suffix) {
                $("#resultCheckOk").hide();
                document.getElementById("errorDetails").innerHTML = "Found " + line[1] + " times in leaks...";
                $("#resultCheckKo").show();
                // Forcément mauvais si dans la DB ! 
                var bar = document.getElementById("pwdStrength");
                bar.setAttribute("class", "progress-bar bg-danger");
                bar.setAttribute("style", "width:25%");
                bar.setAttribute("aria-valuenow", "25");
                bar.innerHTML = "Mauvais !";
                if (typeof lengthPwdGenerate !== 'undefined') {
                    generatePassword(lengthPwdGenerate);
                }

                break;
            } else {
                $("#resultCheckOk").show();
                $("#resultCheckKo").hide();
            }
        }
	getMetaInf();
    });
}

function hex(buffer) {
    var hexCodes = [];
    var view = new DataView(buffer);
    for (var i = 0; i < view.byteLength; i += 4) {
        // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
        var value = view.getUint32(i)
        // toString(16) will give the hex representation of the number without padding
        var stringValue = value.toString(16)
        // We use concatenation and slice for padding
        var padding = '00000000'
        var paddedValue = (padding + stringValue).slice(-padding.length)
        hexCodes.push(paddedValue);
    }

    // Join all the hex strings into one
    return hexCodes.join("");
}

function scorePassword(pass) {
    // Issu de https://stackoverflow.com/a/11268104
    var score = 0;
    if (!pass)
        return score;

    // award every unique letter until 5 repetitions
    var letters = new Object();
    for (var i = 0; i < pass.length; i++) {
        letters[pass[i]] = (letters[pass[i]] || 0) + 1;
        score += 5.0 / letters[pass[i]];
    }

    // bonus points for mixing it up
    var variations = {
        digits: /\d/.test(pass),
        lower: /[a-z]/.test(pass),
        upper: /[A-Z]/.test(pass),
        nonWords: /\W/.test(pass),
    }

    variationCount = 0;
    for (var check in variations) {
        variationCount += (variations[check] == true) ? 1 : 0;
    }
    score += (variationCount - 1) * 10;

    return parseInt(score);
}

function generatePassword(lengthPwd) {
    var charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?,./-=',
        retVal = "";

    for (var i = 0, n = charset.length; i < lengthPwd; ++i) {
        retVal += charset.charAt(Math.floor(Math.random() * n));
    }

    document.getElementById("inputPwd").value = retVal;
    document.getElementById("genPwd").innerHTML = retVal;
    $("#resultGen").show();
    strengthMeter("inputPwd");
    $("#resultCheckOk").hide();
    $("#resultCheckKo").hide();
    checkPwd(lengthPwd);
}

function strengthMeter(passwordFieldId) {

    // init character classes
    var password = document.getElementById(passwordFieldId).value;
    var numEx = /\d/;
    var lcEx = /[a-z]/;
    var ucEx = /[A-Z]/;
    var syEx = /\W/;
    var meterMult = 1;
    var character_set_size = 0;

    // loop over each char of the password and check it per regexes above.
    // weight numbers, upper case and lowercase at .75, 1 and .25 respectively.
    if (numEx.test(password)) {
        character_set_size += 10;
    }
    if (ucEx.test(password)) {
        character_set_size += 26;
    }
    if (lcEx.test(password)) {
        character_set_size += 26;
    }
    if (syEx.test(password)) {
        character_set_size += 32;
    }

    // assume that 100% is a meterMult of maxMulti
    var strength = Math.pow(character_set_size, password.length);

    // init crackers at hashes/second
    // all numbers from a base with GTX 1060 6GB
    var rateMd5 = 11500000000;
    var rateSHA1 = 4400000000;
    var rateSHA256 = 1500000000;
    var rateSHA512 = 550000000;
    var rateMd5crypt = 5150000;
    var rateBcrypt = 6600;
    var ratePBKDF2Sha1 = 1700000;
    var ratePBKDF2Sha512 = 217000;

    // calculate a human readable time based on seconds
    var secMd5 = secondsToStr(toFixed(strength / (rateMd5)));
    var secSHA1 = secondsToStr(toFixed(strength / (rateSHA1)));
    var secSHA256 = secondsToStr(toFixed(strength / (rateSHA256)));
    var secSHA512 = secondsToStr(toFixed(strength / (rateSHA512)));
    var secMd5crypt = secondsToStr(toFixed(strength / (rateMd5crypt)));
    var secBcrypt = secondsToStr(toFixed(strength / (rateBcrypt)));
    var secPbkdf2Sha1 = secondsToStr(toFixed(strength / (ratePBKDF2Sha1)));
    var secPbkdf2Sha512 = secondsToStr(toFixed(strength / (ratePBKDF2Sha512)));

    var rates = "MD5: " + secMd5 + " <br/>" +
        "SHA1 : " + secSHA1 + "<br/>" +
        "SHA256 : " + secSHA256 + "<br/>" +
        "SHA512 : " + secSHA512 + "<br/>" +
        "MD5Crypt : " + secMd5crypt + "<br/>" +
        "Bcrypt : " + secBcrypt + "<br/>" +
        "PBKDF2-HMAC-SHA1 : " + secPbkdf2Sha1 + "<br/>" +
        "PBKDF2-HMAC-SHA512 : " + secPbkdf2Sha512 + "<br/>" +
        " ";

    // if null, don't show anything
    if (password.length > 0) {
        $("#passwordIndicator").show();
        $("#pwdStrength").show();
        $("#possibilities").html(numberWithCommas(strength) + " possibilities");
        $("#rates").html(rates);
    } else {
        $("#passwordIndicator").hide();
        $("#pwdStrength").hide();
    }

    var bar = document.getElementById("pwdStrength");

    var score = scorePassword(password);

    if (score > 80) {
        bar.setAttribute("class", "progress-bar bg-success");
        bar.setAttribute("style", "width:100%");
        bar.setAttribute("aria-valuenow", "100");
        bar.innerHTML = "Top !";
    } else if (score > 60) {
        bar.setAttribute("class", "progress-bar bg-info");
        bar.setAttribute("style", "width:75%");
        bar.setAttribute("aria-valuenow", "75");
        bar.innerHTML = "Good";
    } else if (score > 30) {
        bar.setAttribute("class", "progress-bar bg-warning");
        bar.setAttribute("style", "width:50%");
        bar.setAttribute("aria-valuenow", "50");
        bar.innerHTML = "Medium";
    } else {
        bar.setAttribute("class", "progress-bar bg-danger");
        bar.setAttribute("style", "width:25%");
        bar.setAttribute("aria-valuenow", "25");
        bar.innerHTML = "Bad !";
    }


}

// thanks http://stackoverflow.com/questions/2901102/how-to-print-number-with-commas-as-thousands-separators-in-javascript
function numberWithCommas(x) {
    return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// thanks http://stackoverflow.com/questions/8211744/convert-milliseconds-or-seconds-into-human-readable-form
function secondsToStr(seconds) {
    // TIP: to find current time in milliseconds, use:
    // var milliseconds_now = new Date().getTime();
    seconds = Math.round(seconds);
    var numyears = Math.floor(seconds / 31536000);
    if (numyears) {
        if (numyears < 21000000) {
            return numberWithCommas(numyears) + ' year' + ((numyears > 1) ? 's' : '');
        } else {
            return "More than age of univers...";
        }
    }
    var numdays = Math.floor((seconds % 31536000) / 86400);
    if (numdays) {
        return numdays + ' day' + ((numdays > 1) ? 's' : '');
    }
    var numhours = Math.floor(((seconds % 31536000) % 86400) / 3600);
    if (numhours) {
        return numhours + ' hour' + ((numhours > 1) ? 's' : '');
    }
    var numminutes = Math.floor((((seconds % 31536000) % 86400) % 3600) / 60);
    if (numminutes) {
        return numminutes + ' minut' + ((numminutes > 1) ? 's' : '');
    }
    var numseconds = (((seconds % 31536000) % 86400) % 3600) % 60;
    if (numseconds) {
        return numseconds + ' second' + ((numseconds > 1) ? 's' : '');
    }
    return "Less than a second"; //'just now' //or other string you like;
}

// thanks http://stackoverflow.com/questions/1685680/how-to-avoid-scientific-notation-for-large-numbers-in-javascript
function toFixed(x) {
    if (Math.abs(x) < 1.0) {
        var e = parseInt(x.toString().split('e-')[1]);
        if (e) {
            x *= Math.pow(10, e - 1);
            x = '0.' + (new Array(e)).join('0') + x.toString().substring(2);
        }
    } else {
        var e = parseInt(x.toString().split('+')[1]);
        if (e > 20) {
            e -= 20;
            x /= Math.pow(10, e);
            x += (new Array(e + 1)).join('0');
        }
    }
    return x;
}
