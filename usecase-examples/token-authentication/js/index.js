
//jQuery time
var current_fs, next_fs, previous_fs; //fieldsets
var left, opacity, scale; //fieldset properties which we will animate
var animating; //flag to prevent quick multi-click glitches

$(".display-attributes").select2({width: "100%", multiple:true});

$("#identities").on("click", ".next", function(){
	if(animating) return false;
	animating = true;
	
	current_fs = $(this).parent();
	next_fs = $(this).parent().next();
	
	//activate next step on progressbar using the index of next_fs
	$("#progressbar li").eq($("fieldset").index(next_fs)).addClass("active");
	
	//show the next fieldset
	next_fs.show(); 
	//hide the current fieldset with style
	current_fs.animate({opacity: 0}, {
		step: function(now, mx) {
			//as the opacity of current_fs reduces to 0 - stored in "now"
			//1. scale current_fs down to 80%
			scale = 1 - (1 - now) * 0.2;
			//2. bring next_fs from the right(50%)
			left = (now * 50)+"%";
			//3. increase opacity of next_fs to 1 as it moves in
			opacity = 1 - now;
			current_fs.css({'transform': 'scale('+scale+')'});
			next_fs.css({'left': left, 'opacity': opacity});
		}, 
		duration: 800, 
		complete: function(){
			current_fs.hide();
			animating = false;
		}, 
		//this comes from the custom easing plugin
		easing: 'easeInOutBack'
	});
});

$("#identities").on("click", ".previous1", function(){
	if(animating) return false;
	animating = true;
	
	current_fs = $(this).parent();
	previous_fs = $(this).parent().prev();
	
	//de-activate current step on progressbar
	$("#progressbar li").eq($("fieldset").index(current_fs)).removeClass("active");
	
	//show the previous fieldset
	previous_fs.show(); 
	//hide the current fieldset with style
	current_fs.animate({opacity: 0}, {
		step: function(now, mx) {
			//as the opacity of current_fs reduces to 0 - stored in "now"
			//1. scale previous_fs from 80% to 100%
			scale = 0.8 + (1 - now) * 0.2;
			//2. take current_fs to the right(50%) - from 0%
			left = ((1-now) * 50)+"%";
			//3. increase opacity of previous_fs to 1 as it moves in
			opacity = 1 - now;
			current_fs.css({'left': left});
			previous_fs.css({'transform': 'scale('+scale+')', 'opacity': opacity});
		}, 
		duration: 800, 
		complete: function(){
			current_fs.hide();
			animating = false;
		}, 
		//this comes from the custom easing plugin
		easing: 'easeInOutBack'
	});
});

$("#attributes").on("click", ".next", function(){
	if(animating) return false;
	animating = true;
	
	current_fs = $(this).parent();
	next_fs = $(this).parent().next();
	
	//activate next step on progressbar using the index of next_fs
	$("#progressbar li").eq($("fieldset").index(next_fs)).addClass("active");
	
	//show the next fieldset
	next_fs.show(); 
	//hide the current fieldset with style
	current_fs.animate({opacity: 0}, {
		step: function(now, mx) {
			//as the opacity of current_fs reduces to 0 - stored in "now"
			//1. scale current_fs down to 80%
			scale = 1 - (1 - now) * 0.2;
			//2. bring next_fs from the right(50%)
			left = (now * 50)+"%";
			//3. increase opacity of next_fs to 1 as it moves in
			opacity = 1 - now;
			current_fs.css({'transform': 'scale('+scale+')'});
			next_fs.css({'left': left, 'opacity': opacity});
		}, 
		duration: 800, 
		complete: function(){
			current_fs.hide();
			animating = false;
		}, 
		//this comes from the custom easing plugin
		easing: 'easeInOutBack'
	});
});

$(".next").click(function(){
	if(animating) return false;
	animating = true;
	
	current_fs = $(this).parent();
	next_fs = $(this).parent().next();
	
	//activate next step on progressbar using the index of next_fs
	$("#progressbar li").eq($("fieldset").index(next_fs)).addClass("active");
	
	//show the next fieldset
	next_fs.show(); 
	//hide the current fieldset with style
	current_fs.animate({opacity: 0}, {
		step: function(now, mx) {
			//as the opacity of current_fs reduces to 0 - stored in "now"
			//1. scale current_fs down to 80%
			scale = 1 - (1 - now) * 0.2;
			//2. bring next_fs from the right(50%)
			left = (now * 50)+"%";
			//3. increase opacity of next_fs to 1 as it moves in
			opacity = 1 - now;
			current_fs.css({'transform': 'scale('+scale+')'});
			next_fs.css({'left': left, 'opacity': opacity});
		}, 
		duration: 800, 
		complete: function(){
			current_fs.hide();
			animating = false;
		}, 
		//this comes from the custom easing plugin
		easing: 'easeInOutBack'
	});
});

$(".previous").click(function(){
	if(animating) return false;
	animating = true;
	
	current_fs = $(this).parent();
	previous_fs = $(this).parent().prev();
	
	//de-activate current step on progressbar
	$("#progressbar li").eq($("fieldset").index(current_fs)).removeClass("active");
	
	//show the previous fieldset
	previous_fs.show(); 
	//hide the current fieldset with style
	current_fs.animate({opacity: 0}, {
		step: function(now, mx) {
			//as the opacity of current_fs reduces to 0 - stored in "now"
			//1. scale previous_fs from 80% to 100%
			scale = 0.8 + (1 - now) * 0.2;
			//2. take current_fs to the right(50%) - from 0%
			left = ((1-now) * 50)+"%";
			//3. increase opacity of previous_fs to 1 as it moves in
			opacity = 1 - now;
			current_fs.css({'left': left});
			previous_fs.css({'transform': 'scale('+scale+')', 'opacity': opacity});
		}, 
		duration: 800, 
		complete: function(){
			current_fs.hide();
			animating = false;
		}, 
		//this comes from the custom easing plugin
		easing: 'easeInOutBack'
	});
});

function gen_idtiles(identities) {
	for (var i = 0; i < identities.length; i++) {
	    $("#identities").append("<input type='button' name='next' class='next action-button' onclick=submit_id('" + identities[i] + "') value=" + identities[i] + " />");
	}
}

function gen_attributes(attributes) {
	for (var i = 0; i < attributes.length; i++) {
	    $(".display-attributes").append("<option value=" + attributes[i] + ">" + attributes[i] + "</option>");
	}
}

function gen_decattributes(attributes) {
	for (var i = 0; i < attributes.length; i++) {
		for (j in attributes[i]) {
	    	$("#decrypted").append("<h3>" + j + "  :  " + attributes[i][j] + "</h3></br>");
	    }
	}
}

$('#auth_btn').click(function(){
    $.get('http://127.0.0.1:8080/auth', function(identities) {
    	if (identities) {
        	gen_idtiles(identities['identities']);
        }
        else {
		    $("#identities").append('<li><input type="button" name="previous" class="previous1 action-button" value="Previous" /></li>');

        	console.log("You either have no identities or the Identity API is not turned on.")
        }
    });
});

function submit_id(identity) {
	console.log("You have chosen:", identity);
	$.ajax({
	    url : "/identity",
	    type: "POST",
	    data : JSON.stringify({'name':identity}),
	    contentType: 'application/json',
	    success: function(data, textStatus, jqXHR)
	    {
	        gen_attributes(data['attributes']);
	    },
	    error: function (jqXHR, textStatus, errorThrown)
	    {
	 		console.log("Something went wrong")
	    }
	});
}

function getattributes() {
	attributes = $(".display-attributes").select2("val");
	console.log("Your chosen attributes:", attributes);
	$.ajax({
	    url : "/attributes",
	    type: "POST",
	    data : JSON.stringify({'name':attributes}),
	    contentType: 'application/json',
	    success: function(data, textStatus, jqXHR)
	    {
	        console.log("Recieved Token:", data['decrypted']);
	        value = data['decrypted'].split(".");
	        header = window.atob(value[0]);
	        body = window.atob(value[1]);
	        sig = value[2];
	        console.log(header);
	        console.log(body);
	        gen_decattributes(JSON.parse(body.replace(/'/g , '"')));
	    },
	    error: function (jqXHR, textStatus, errorThrown)
	    {
	 		console.log("Something went wrong")
	    }
	});
}