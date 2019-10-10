function closeMe (frm) {
	frm.style.display = "none";
	frm.reset();
}
function closeAndInit (frm) {
	closeMe(frm);
	document.userForm.style.display = "block";
	document.userForm.inUser.focus();
}
function showMsg (button, msg) {
	button.disabled = true;
	var oldVal = button.value;
	var oldColor = button.style.background;
	if (msg == "Success")
		button.style.background = "#32CD32";
	else button.style.background = "#FF7F50";
	button.value = msg;
	setTimeout (function () {
		button.value = oldVal;
		button.style.background = oldColor;
		button.disabled = false;
	}, 2000);
}
function callback () {
	if (this.readyState != 4) 
		return;
	if (this.status != 200) {
		showMsg(this.frm.click, "HTTP Error");
		return;
	}
	if (!this.responseText) {
		showMsg(this.frm.click, "App Error");
                return;
	}
	var data = JSON.parse(this.responseText);
	if (!data || !data.rc) {
		showMsg(this.frm.click, "App Error");
		return;
	}
	if (this.frm.name == "avpForm") {
		showMsg(this.frm.click, "Success");
		return;
	}
	closeMe(this.frm);
	var frm = document.avpForm;
	var elms = frm.elements;
	document.getElementById("userName").innerText = data.username;
	for (var i = 0; i < elms.length ; i++) {
              	if (elms[i].type != "text")
               		continue;
		if (data[elms[i].className] && 
		    data[elms[i].className][elms[i].id])
			elms[i].value = data[elms[i].className][elms[i].id];
	}
	frm.style.display = "block";
	elms[0].focus();
}	
function getUser (frm) {
	if (!frm.inUser.value){
		frm.inUser.focus(); 
		return false;
	}
	var postStr = new Object();
	postStr.username = frm.inUser.value;
	postStr.action = "get";
	ajax(postStr, frm);
	return false;
}
function setUser (frm) {
	var postStr = new Object();
	var elms = frm.elements;
	postStr.username = document.getElementById("userName").innerText;
	postStr.action = "set";
        for (var i = 0; i < elms.length ; i++) {
		if (elms[i].type != "text" || !elms[i].value)
				continue;
		if (!postStr[elms[i].className])
			postStr[elms[i].className] = {};
		postStr[elms[i].className][elms[i].id] = elms[i].value;
	}
	ajax(postStr, frm);
	return false;
}
        
function ajax (post, frm) {
	var url = "ajax.php";
	var xhr = new XMLHttpRequest();
	xhr.frm = frm;
	xhr.onreadystatechange = callback;
	xhr.open("POST", url, true);
	xhr.setRequestHeader('Content-Type', 'application/json;');
	xhr.timeout = 5000;
	xhr.ontimeout = function () { showMsg(frm.click, "Timed Out"); } 
	xhr.send(JSON.stringify(post));
}
