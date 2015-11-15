$(function(){

    function update(params) {
        return function(){
            params.id = $(this).data('id');
            $(this).prop('disabled', true);
            $.ajax({
                url:'/update',
                type: 'POST',
                data: JSON.stringify(params),
                contentType: 'application/json; charset=utf-8',
                dataType: 'json',
                timeout: 8000,
                success: function() {
                    location.reload();
                },
                error: function() {
                    $(this).prop('disabled', false);
                }
            });
        }
    }

    $('input.accept-btn').click(update({approved:true}));
    $('input.assign-btn').click(update({role:1}));

});