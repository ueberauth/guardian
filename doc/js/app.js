function fixOutsideWorldLinks() {
  $('a').each(function() {
    if (window.location.host != this.host) this.target = '_parent';
  });
}

$(fixOutsideWorldLinks);
