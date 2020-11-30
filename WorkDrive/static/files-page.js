function slugify(name){
    if (!name){
        return "";
    }
    return name.replace(' ','-').replace('*','-').replace('+','-');
}


$('.btn-share-file').on('click', function(){
    const $this=$(this);
    $('#shareModal').modal();
    console.log("Modal is now shown");

    const fileId=$this.attr('data-file-id');
    console.log("File Id is " + fileId);
    const fileName=$this.attr('data-file-name');
    const fileNameSlugified= slugify(fileName);

    const permalink='http://localhost:5000' + '/download/' + fileId + '/' + fileNameSlugified;
    console.log("Permalink is " + permalink);
    $('#shareModal .share-link').html(permalink);
});