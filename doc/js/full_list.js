var inSearch = null;
var defaultSearchItemTimeOut = 0; //set to "0" if not testing
var searchIndex = 0;
var searchCache = [];
var searchString = '';
var regexSearchString = '';
var caseSensitiveMatch = false;
var ignoreKeyCodeMin = 8;
var ignoreKeyCodeMax = 46;
var commandKey = 91;

RegExp.escape = function(text) {
  return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");
}

function fullListSearch() {
  // generate cache
  searchCache = [];
  $('#full_list li').each(function() {
    var link = $(this).find('a.object_link:first');
    if ( link.attr('title') ) {
      var fullName = link.attr('title').split(' ')[0];
      searchCache.push({name:link.text(), fullName:fullName, node:$(this), link:link});
    }
  });

  $('#search input').keypress(function (e) {
    if (e.which == 13) {
        $('#full_list li.found:first').find('a.object_link:first').click();
    }
  });

  //$('#search input').keyup(function(evnt) {
  $('#search input').bind("keyup search reset change propertychange input paste", function(evnt) {
    if ((evnt.keyCode > ignoreKeyCodeMin && evnt.keyCode < ignoreKeyCodeMax)
         || evnt.keyCode == commandKey) {
      return;
    }

    $('#search').addClass('loading');
    searchString = this.value;
    caseSensitiveMatch = searchString.match(/[A-Z]/) != null;
    regexSearchString = RegExp.escape(searchString);
    if (searchString === "") {
      showAllResults();
    }
    else {
      if (inSearch) {
        clearTimeout(inSearch);
      }
      searchIndex = 0;
      lastRowClass = '';
      $('#content').addClass('in_search');
      $('#no_results').text('');
      searchItem();
    }    
  });

  $('#search input').focus();
}

function showAllResults() {
  clearTimeout(inSearch);
  inSearch = defaultSearchItemTimeOut;
  $('.search_uncollapsed').removeClass('search_uncollapsed');
  $('#content').removeClass('in_search');
  $('#full_list li').removeClass('found').each(function() {
    var link = $(this).find('a.object_link:first');
    link.text(link.text()); 
  });
  if (clicked) {
    clicked.parents('li').each(function() {
      $(this).removeClass('collapsed').prev().removeClass('collapsed');
    });
  }
  $('#no_results').text('');
  $('#search').removeClass('loading');
  highlight();
}

var lastRowClass = '';
function searchItem() {
  for (var i = 0; i < searchCache.length / 50; i++) {
    var item = searchCache[searchIndex];
    var searchName = (searchString.indexOf('.') != -1 ? item.fullName : item.name);
    var matchString = regexSearchString;
    var matchRegexp = new RegExp(matchString, caseSensitiveMatch ? "" : "i");
    if (searchName.match(matchRegexp) == null) {
      item.node.removeClass('found');
    }
    else {
      item.node.addClass('found');
      item.node.parents('li').addClass('search_uncollapsed');
      item.node.removeClass(lastRowClass).addClass(lastRowClass == 'r1' ? 'r2' : 'r1');
      lastRowClass = item.node.hasClass('r1') ? 'r1' : 'r2';
      item.link.html(item.name.replace(matchRegexp, "<strong>$&</strong>"));
    }

    if (searchCache.length === searchIndex + 1) {
      searchDone();
      return;
    }
    else {
      searchIndex++;
    }
  }
  inSearch = setTimeout('searchItem()', defaultSearchItemTimeOut);
}

function searchDone() {
  highlight(true);
  if ($('#full_list li.found').size() === 0) {
    $('#no_results').text('No results were found.').hide().fadeIn();
  }
  else {
    $('#no_results').text('');
  }

  $('#search').removeClass('loading');
  clearTimeout(inSearch);
  inSearch = null;
}

clicked = null;
function linkList() {
  $('#full_list li, #full_list li a:last').click(function(evt) {
    if ($(this).hasClass('toggle')) {
      return true;
    }

    if (this.tagName.toLowerCase() == "li") {
      var toggle = $(this).children('a.toggle');
      if (toggle.size() > 0 && evt.pageX < toggle.offset().left) {
        toggle.click();
        return false;
      }
    }

    if (clicked) {
      clicked.removeClass('clicked');
    }
    
    var win = window.top.frames.main ? window.top.frames.main : window.parent;
    if (this.tagName.toLowerCase() == "a") {
      clicked = $(this).parent('li').addClass('clicked');
      win.location = this.href;
    }
    else {
      clicked = $(this).addClass('clicked');
      win.location = $(this).find('a:last').attr('href');
    }

    return false;
  });
}

function collapse() {
  $('#full_list a.toggle').click(function() { 
    $(this).parent().toggleClass('collapsed').next().toggleClass('collapsed');
    highlight();
    return false; 
  });
  
  $('#full_list > li.node').each(function() {
    $(this).addClass('collapsed').next('li.docs').addClass('collapsed');
  });
  
  highlight();
}

function highlight(no_padding) {
  var n = 1;
  $('#full_list a.object_link:visible').each(function() {
    var next = n == 1 ? 2 : 1;
    var li = $(this).parent();
    li.removeClass("r" + next).addClass("r" + n);
    no_padding ? li.addClass("no_padding") : li.removeClass("no_padding");
    n = next;
  });
}

function escapeShortcut() {
  $(document).keydown(function(evt) {
    if (evt.which == 27) {
      $('#search_frame', window.top.document).slideUp(100);
      $('#search a', window.top.document).removeClass('active inactive');
      $(window.top).focus();
    }
  });
}

$(escapeShortcut);
$(fullListSearch);
$(linkList);
$(collapse);