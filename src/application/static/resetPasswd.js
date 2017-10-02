/*
Copyright 2017 Ryan David Williams

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

let MINIMUM_PASSWORD_SCORE = 60;

function checkPasswordMatch() {
    var password = $("#userNewPass").val();
    var password_score = scorePassword(password);
    var confirmPassword = $("#userNewPassConfirm").val();

    password.needs_confirm = true;

    if (password.length > 0) {
        $("#divCheckPassword").show();
        if (password != confirmPassword) {
            $("#divCheckPassword").html("Passwords do not match!");
            $("#self_reset_submit").each(function(){ this.disabled = true});
        } else if (password_score >= MINIMUM_PASSWORD_SCORE) {
            $("#divCheckPassword").html("Passwords match.");
            $("#self_reset_submit").each(function(){ this.disabled = false});
        } else {
            $("#self_reset_submit").each(function(){ this.disabled = true});
            $("#divCheckPassword").html("Password not complex enough.");
        }
    } else {
        $("#divCheckPassword").hide();
        $("#self_reset_submit").each(function(){ this.disabled = true});
    }
}

function scorePassword(pass) {
    var score = 0;
    if (!pass)
        return score;

    // award every unique letter until 5 repetitions
    var letters = new Object();
    for (var i=0; i<pass.length; i++) {
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

function checkPassStrength() {
    var pass = $(this).val();
    var score = scorePassword(pass);
    var str_div = $(this).parent().siblings('.new_pass_str');
    if (pass.length > 0) {
        str_div.show()
        if (score > 80) {
            str_div.html('Strength: Good (' + score + ')');
            return;
        }
        if (score > 60) {
            str_div.html('Strength: Ok (' + score + ')');
            return;
        }
        str_div.html('Strength: Fail (' + score + ')');
    } else {
        str_div.hide()
    }
}

function checkMinimumStrength() {
    var pass = $(this).val();
    var score = scorePassword(pass);
    if (score >= MINIMUM_PASSWORD_SCORE && pass.length > 0)
        $("#direct_reset_submit").each(function(){ this.disabled = false});
    else
        $("#direct_reset_submit").each(function(){ this.disabled = true});
}

$(document).ready(function () {
   $("#userNewPass, #userNewPassConfirm").keyup(checkPasswordMatch);
   $(".reset_submit").each(function(){ this.disabled = true});
   $('#userNewPass, #adminNewPass').keyup(checkPassStrength);
   $('#adminNewPass').keyup(checkMinimumStrength);
   $('#select_email_reset_users').select2({placeholder: "users"});
});
