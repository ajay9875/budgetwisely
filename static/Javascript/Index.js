function displaydetails(){
    let details = document.getElementById('profile-details');
    if (details.style.display ==='none' || details.style.display ==='' ){
        details.style.display = 'block';
    }
    else{
        details.style.display = 'none';
    }
}
