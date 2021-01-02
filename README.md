# image-repo

An image repository project that can be accessed at: https://image-repo-project.herokuapp.com/

Or you can clone the repo and do pip install -r requirements.txt and flask run (this was developed with python 3.7.5)

## Accounts & Login

You can create an account or use at pre-created one. (Username: rishi, Password: password)

Must login to use the repository. Requires a relogin after 30 mins for security purposes

## Images

You are able to upload images with the image being public (every user can see it) or private (only you can see it). This can be modified in the all images/search image results per individual image.

When uploading it is also possible to select more then one image in the upload popup to mass import images. 

Uploaded images use a generated image id for it's file name as to prevent unsecure access

The images are run through a function which gets the most common colour of the image 

The images are also sent to a machine learning api which returns the top 3 classifications of said image

Images can also be downloaded from the search results/all image pages

## Searching

You can search for the most common colour or any of the top 3 classifcations. 

It is also possible to click the tags under the image in the all images/search results page to make that your search parameter

## Deleting 

Images can be deleted from the all images/search images screen.

Deleting an image will remove it's information from the database and remove it from the file system

## Permissions 

If you are the user who uploaded the image it is possible to make it private from public or vice-versa

If you are the user who uploaded the image it is possible to delete it 

Both of these options are unavailible to users who are not the uploader
