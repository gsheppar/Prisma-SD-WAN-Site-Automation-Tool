$(document).ready(function(){
  var output = document.getElementById('output');
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '{{ url_for('log_stream') }}', true);
  xhr.send();
  setInterval(function() {
    output.textContent = xhr.responseText;
  }, 500);
});
