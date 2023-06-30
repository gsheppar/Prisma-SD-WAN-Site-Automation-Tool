$(function() {
    $('#login-tab').show();
    $('#register-tab').show();

    $('#myTab a').click(function(e) {
        e.preventDefault();
        if (($(this).attr('id') == 'login-tab')) {
            $('#register').hide();
            $('#login').show();
        }
        if (($(this).attr('id') == 'register-tab')) {
            $('#login').hide();
            $('#register').show();
        }
      })

});
