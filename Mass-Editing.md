# Automated repeated editing

Computers allow for automation and repeating tasks.  Hence it is possible to repleat the same task over many files.

For example:

You have an ansible script (yaml) file that performs a curl command to a website, but you are developing the code and use "localhost" for the website.  Great in your local machine, but what happens when this is deployed into the real world?  It will work if it is on the same host, but that is not a given.  

However, you have generated many files in a whole directory structure that contains http://localhost:8080/ in the files and editing more than one of these will be slow.

```shell
curl  'https://localhost:8080'
```

## Searching in files

You can search for the files using grep within a single folder:

```shell
grep -E 'http(.*)localhost:' *
```
Which will list all the lines which contain "http" followed by any characters (.*) on the same line with "localhost:"


## Searching for files

If you need to search a directory structure, then the `find` command becomes your friend, as this can search through the file system, 
for files, directories, by name, age, size etc and also perform other commnands on files that match your criteria.

In this case we wish to search for `*.yaml` files from the `~/src` directory:

`find ~/src -name "*.yaml" -print`

This will list all paths, relative to the ~/src.  To see more file details (size, permissions etc), use -ls instead of print:

`find ~/src -name "*.yaml" -ls`

## Searching for files and inside the files found

So we can now find yaml files and we can search files for content, how can we combine these, simple, use the -exec option in find:

`find ~/src -name "*.yaml" -exec grep -E 'http(.*)localhost:' {} \; -ls`

Two things to note:
 1. The "{}" in the command is replaced by the file that matches the find criteria (name of *.yaml)
 2. The "\;" terminates the -exec option.

>   Note that the "-ls" at the end will now only list the files that grep has successfully matched the localhost search pattern.  This is
>   because each component of the find command is a logical AND, only passing on results that match.  Hence
```shell
   find ~/src                 #--> returns all files
   find ~/src -name "*.yaml"  #--> returns only "*.yaml" files
   find ~/src -name "*.yaml" -exec grep -E 'http(.*)localhost:' {} \; #--> print file name of only *.yaml files that contain "http*localhost:"
   find ~/src -name "*.yaml" -exec grep -E 'http(.*)localhost:' {} \; -ls  #--> print the full file details that match as above

```
Because the "-ls" is at the end of the command, it will be printed _after_ the output from grep.

That is great, so we can see the files that need changing, but how do we change them?

Two commands generally used to manipulate files are `sed` and `awk`, to the degree that there is a book on [sed and awk commands](https://www.oreilly.com/library/view/sed-awk/1565922255/) published by O'Reilly .

In this instance, just sed will suffice.  We want to change localhost to an ansible variable of the __service_url__, which can be done with:

`sed -re 's#(http.*)localhost:#h\1{{ service_url }}#g' get_localhost_info.yaml`

>NOTE:  `sed` expressions have several commands, the one used here is "s" to substitute one string pattern for 
>the next.  The "s" command will use WHATEVER character follows as the separator, usually "/" is used, but since "/" is generally used in URLS and '#' is not, I have used '#' in this example.  
>The "#g" at the end of the "s" command is the last "#" separator and "global" flag to replace all instances of the match on the line, so if the pattern matches more than once, all the patterns get replaced.  
>Without the "g" option, only the first is replaced.
>
> See [Sed Tutorial](https://www.grymoire.com/Unix/Sed.html) for a tutorial on sed.

This will output the __S__ tream __ED__ ited (sed) version of the file.  The option "-re" is two options -r (use regular expression syntax) and -e (expression option).  
The "(" and ")" wrap around the part of the found text that will be used in the replacement by using "\1" followed by the replacement text to replace localhost.

However, this does not change the file.  This needs another argument "-i" (inline editing), which instructs sed to edit the given file with the changes directly.  At this point it is worth saying, you __really__ 
want to make sure this is what you want, or hae a backup of the files, as this has the potential of editing your file away, if you put something interesting in the sed expression, which is why I like to confirm that it is 
doing what I expect and don't go straight into using "-i" option, without first knowing what the search pattern will match.

`sed -i -re 's#(http.*)localhost:#h\1{{ service_url }}#g' get_localhost_info.yaml`

> NOTE: "-i" and "-re" need to be separate. 

## Combine the find and replace commands

To combine the find and replace commands, we just need to add another `-exec` option to the find command after the grep and before the -ls, replace the file name with "{}" and terminate the command with "\;":

`find ~/src -name "*.yaml" -exec grep -E 'http(.*)localhost:' {} \; -exec sed -i -re 's#(http.*)localhost:#h\1{{ service_url }}#g' {} \; -ls`

But that is a long line and hard to read when you look at again for next time this problem crops up, so we an use the "escape" character to escape the newline and make this a multi-line command:

```
find ~/src -name "*.yaml" \
    -exec grep -E 'http(.*)localhost:' {} \; \
    -exec sed -i -re 's#(http.*)localhost:#h\1{{ service_url }}#g' {} \; \
    -ls
```

> NOTE that the newline is the only thing after the "\" on the lines, no spaces.

That works, but you get lots of output on the screen that you don't need, so we can make grep run quietly, by adding the "-q" option:

```
find ~/src -name "*.yaml" \
    -exec grep -qE 'http(.*)localhost:' {} \; \
    -exec sed -i -re 's#(http.*)localhost:#h\1{{ service_url }}#g' {} \; \
    -ls
```

