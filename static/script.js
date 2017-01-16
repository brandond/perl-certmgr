var SanChanged = false;

$(document).ready(function() {
  switchCertUpload();
  setKeyUsage();
  splitSAN();
  $('form#new').validate();
  $('form#copy').submit(validateSAN).validate();
  $('form#update').validate();
  $('form#create').validate();
  $('input[name=cert_type]').change(switchCertUpload);
  $('input#CN').keyup(autoBuildSANs);
  $('textarea#sans').change(function(){ SanChanged = true; });
});

function autoBuildSANs(){
  if (SanChanged)
    return;
  var cn = $('input#CN').val().trim();
  var cnParts = cn.split('.');
  var autoSans = 'dns:'+cn;
  if (cnParts.length > 2){
    if (cnParts[0] == '*'){
      cnParts.shift();
      autoSans += ', dns:'+Array.join(cnParts, '.');
    } else {
      autoSans += ', dns:'+cnParts[0];
    }
  }
  $('textarea#sans').val(autoSans);
};

function switchCertUpload(){
  var selected = $('input[name=cert_type]:checked').val();
  var notSelected = (selected == 'cert_file' ? 'cert_text' : 'cert_file');
  $('div.'+selected).show();
  $('input,textarea').filter('[name='+selected+']').attr('required', 'true');
  $('div.'+notSelected).hide();
  $('input,textarea').filter('[name='+notSelected+']').removeAttr('required')
};

function splitSAN() {
  var sans = $('textarea').val();
  if (sans && sans.length){
    $('textarea').val(sans.replace(/, /g, ",\r\n"));
  }
}

function validateSAN(ev){
  var namePat = /^(ip|dns|uri|email)$/i
  var sans = $('textarea[name="sans"]').val().replace(/\s+/g, '');
  var valid = true;
  var newSans = '';
  if(sans && sans.length){
    $.each(sans.split(','), function(i, name){
      var parts = name.split(':');
      if (! namePat.test(parts[0])){
        alert('Invalid Subject Alternative Name entry: '+name);
        valid = false;
      } else {
        if (newSans != '')
          newSans = newSans + ', ';
        newSans = newSans + parts[0].toUpperCase() + ':' + parts[1];
      }
    });
  }
  if (valid){
    $('input[name="2.5.29.17"]').val(newSans);
  } else {
    ev.preventDefault();
    return false;
  }
}

function setKeyUsage() {
  var keyUsage = new Array();
  keyUsage = keyUsage.concat(($("input[name='2.5.29.15_var']").val() || '').split(', '));
  keyUsage = keyUsage.concat(($("input[name='2.5.29.37_var']").val() || '').split(', '));
  
  $.each(keyUsage, function(i, value){
    $('input:checkbox[value="'+value+'"]').prop('checked', true);
  });
}
