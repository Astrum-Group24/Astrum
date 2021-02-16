
function validateScanForm() {

    var x = document.forms['scanForm']['host'].value;
    if (x === '') {
        alert("Host field may not be blank");
        return false;
    }

}