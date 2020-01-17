Plugin for IDA Pro

**Table of Contents**

* [About](#user-content-about)
* [Installation](#user-content-installation)
* [Configuration](#user-content-configuration)
* [Features](#user-content-features)
    * [Structure reconstruction](#user-content-structure)
    * [Decompiler output manipulation](#user-content-manipulation)
    * [Classes](#user-content-classes)
    * [Structure Graph](#user-content-graph)
    * [API](#user-content-api)
* [Presentations](#user-content-presentations)

About
=====

The plugin assists in the creation of classes/structures and detection of virtual tables. It also facilitates transforming decompiler output faster and allows to do some stuff which is otherwise impossible.

**Note**: The plugin supports IDA Pro 7.x with Python 2/3.

Installation
============

Just copy `HexRaysPyTools.py` file and `HexRaysPyTools` directory to Ida plugins directory.

Configuration
============

Can be found at `IDADIR\cfg\HexRaysPyTools.cfg`

* `debug_message_level`. Set 10 if you have a bug and want to show the log along with the information about how it was encountered in the issue.
* `propagate_through_all_names`. Set `True` if you want to rename not only the default variables for the [Propagate Name](#Propagate) feature.
* `store_xrefs`. Specifies whether to store the cross-references collected during the decompilation phase inside the database. (Default - True)
* `scan_any_type`. Set `True` if you want to apply scanning to any variable type. By default, it is possible to scan only basic types like `DWORD`, `QWORD`, `void *` e t.c. and pointers to non-defined structure declarations.

Features
========

**[Recently added][feature_history]**

Structure reconstruction
------------------------

The reconstruction process usually comprises the following steps:

1) Open structure builder.
2) Find a local variable that points to the structure you would like to reconstruct.
3) Apply "Scan variable". It will collect the information about the fields that were accessed in the boundaries of one function. As an option, you can apply "Deep Scan variable", which will do the same thing but will also recursively visit other functions that has the same variable as its argument.
4) After applying steps 2 and 3 enough times, resolve conflicts in the structure builder and finalize structure creation. All the scanned variables will get a new type. Also, cross-references will be remembered and usable anytime.

Now, a few more details.

### Structure Builder (Alt + F8)

The place where all the collected information about the scanned variables can be viewed and modified. Ways of collecting information:
* Right Click on a variable -> Scan Variable. Recognizes fields usage within the current function.
* Right Click on a variable -> Deep Scan Variable. First, recursively touches functions to make Ida recognize proper arguments (it happens only once for each function during a session). Then, it recursively applies the scanner to variables and functions, which get the structure pointer as their argument.
* Right Click on a function -> Deep Scan Returned Value. If you have the singleton pattern or the constructor is called in many places, it is possible to scan all the places, where a pointer to an object was recieved or an object was created.
* API [TODO]

![img][builder]

Structure builder stores collected information and enables interaction:

* Types with the __BOLD__ font are virtual tables. A double click opens the list with all virtual functions, which helps to visit them. The visited functions are marked with a cross and color:

![img][virtual_functions]

* Types with the _ITALIC_ font have been found as passed argument. It can help in finding substructures. [TODO]
* Double click on field `Name` or `Type` to edit.
* Double click on `Offset` opens a window with all the places, where this field has been extracted. Click the "Ok" button to open a selected place in the pseudocode window:

![img][scanned_variables]

Buttons serve the following purpose:

__Finalize__ - opens a window with an editable C-like declaration and assigns new types to all scanned variables.

__Disable__, __Enable__ - are used for collision resolution.

__Origin__ - switches the base offset which is used to produce new fields to structure (this value will be added to every offset of a newly-scanned variable, default = 0).

__Array__ - renders a selected field as an array the size of which is automatically calculated.

__Pack__ - creates and substitutes a substructure for selected items (collisions for these items should be resolved).

__Unpack__ - dismembers a selected structure and adds all its fields to the builder.

__Remove__ - removes the information about selected fields.

__Clear__ - clears all.

__Recognize Shape__ - looks for appropriates structure for selected fields.

__Resolve Conflicts (new)__ - attempts to disable less meaningful fields in favor of more useful ones. (`char` > `_BYTE`, `SOCKET` > `_DWORD` etc). Doesn't help to find arrays.

### Structure Cross-references (Ctrl + X)

With HexRaysPyTools, every time the F5 button is pressed and code is decompiled, the information about addressing to fields is stored inside cache. It can be retrieved with the "Field Xrefs" menu. So, it is better to apply reconstructed types to as many locations as possible to have more information about the way structures are used.

Note: IDA 7.4 has now an official implementation of this feature, available through Shift-X hotkey.

### Guessing Allocation

**Warning!! Very raw feature.** The idea is to help find where a variable came from so as to run Deep Scan Process at the very top level and not to skip large amounts of code.

### Structures with given size

Usage:

1. In Pseudocode viewer, right click on a number -> "Structures with this size". (hotkey "W")
2. Select a library to be looked for structures.
3. Select a structure. The Number will become `sizeof(Structure Name)`, and type will be imported to Local Types.

### Recognition of structures by shapes

Helps find a suitable structure by the information gleaned from pseudocode after variable scanning.

Usage:

* _Method 1_
    1. Right click on a variable with -> Select "Recognize Shape".
    2. Select Type Library.
    3. Select structure.
    4. Type of the variable will be changed automatically.
* _Method 2_
    1. Clear Structure Builder if it's currently used.
    2. Right click on the variables that are supposed to be the same -> "Scan Variable".
    3. Edit types (will be implemented later), disable or remove uninteresting fields, and click the "Recognize Shape" button.
    4. You can select several fields and try to recognize their shapes. If found and selected, they will be replaced with a new structure.
    5. After final structure selection, types of all scanned variables will be changed automatically.

## Disassembler code manipulations  <a name="Manipulations"></a>

### Containing structures

Helps find containing structure and makes code prettier by replacing pointers with [CONTAINING_RECORD][1] macro

__Before:__

![img][bad_structures]

__After:__

![img][good_structures]

Usage:

If a variable is a structure pointer and there's an access to outside of the boundaries of that structure, then:

1. Right click -> Select Containing Structure.
2. Select Type Library.
3. Select appropriate Structure and Offset.
4. If the result does not satisfy the requirements, then Right Click -> Reset Containing Structure and go back to step 1.

### Function signature manipulation

1. Right click first line -> "Remove Return" converts return type to void (or from void to _DWORD).
2. Right click on argument -> "Remove Argument" disposes of this argument.
3. Right click on convention -> "Convert to __usercall" switches to __usercall or __userpurge (same as __usercall but the callee cleans the stack).

### Recasting (Shift+R, Shift+L), Renaming (Shift+N, Ctrl+Shift+N)

Every time you have two sides in an expression, where each side may be a local or global variable, argument or return value of the function signature, it is possible to right-click or press the hotkey to give both sides of the expression similar types. Below, there is the table of possible conversions:

| Original | Shift+L | Shift+R
| --- | --- | --- |
| var = (TYPE) expr | var type -> TYPE  |  |
| exp = (TYPE) var |  | var type -> TYPE |
| function(..., (TYPE) var, ...) | functions' argument -> TYPE | var type -> TYPE |
| (TYPE) function(...) | | functions' return type -> TYPE |
| return (TYPE) var | functions' return type -> TYPE | var type -> TYPE |
| struct.field = (TYPE) var | type(field) -> TYPE | |
| pstruct->field = (TYPE) var | type(field) -> TYPE | |

When you have an expression like `function(..., some_good_name, ...)`, you can rename function parameter.

When you have an expression like `function(..., v12, ...)`, and function has an appropriate parameter name, you can quickly apply this name to the variable.

Also possible to rename `vXX = v_named` into `_v_named = v_named` and vice versa.

And there's a feature for massive renaming functions using assert statements. If you find a function that looks like an assert, right-click the string argument with the function name and select "Rename as assert argument". All the functions where a call to assert statement has happened will be renamed (provided that there is no conflicts, either way, you'll see the warning in the output window)

### Name Propagation (P)

This feature does the same recursive traversal over functions as the Deep Scan Variable does. But this time, all elements that have a connection with the selected one receive its name. It’s possible to rename it or use names of both local and global variables, as well as structure members. By default, the plugin propagates names only over default names like `v1`, `a2`. See **Configuration** in order to change that.

### Untangling 'if' statements

* Clicking `if` manually allows to switch `then` and `else` branches
* Automatically applies the following transformations:

Before:

```c
...
if (condition) {
    statement_1;
    statement_2;
    ...
    return another_value;
}
return value;
```

After:
```c
...
if (opposite_condition) {
    return value;
}
statement_1;
statement_2;
...
return another_value;            // if 'then' branch has no return, than `return value;`
```

Classes
-------

Also, it can be found at _View->Open Subview->Classes_. Helps to manage classes (structures with virtual tables).

![img][classes]

##### !! Better to rename all functions before debugging, because Ida can mess up default names, and the information in virtual tables will be inconsistent.

Class, virtual tables, and functions names are editable. Also a function's declaration can be edited. After editting, the altered items change font to _italic_. Right click opens the following menu options:

* Expand All / Collapse All.
* Refresh - clear all and rescan local types for information again.
* Rollback - undo changes.
* Commit - apply changes. Functions will be renamed and recasted both in virtual tables in Local Types and disassembly code.
* Set First Argument type - allows selecting the first argument for a function among all classes. If right click was used on class name, then its type will be automatically applied to the virtual table at offset 0.

You can also filter classes using Regexp either by class_name or by existence of specific functions. Simply input an expression in line edit for filtering by class_name or prepend it with "!" to filter by function name.

Structure Graph
---------------

Shows relationship between structures:

![img][structure_graph]

Also: dark green node is union, light green - enum.

Usage:

1. Open Local Types.
2. Select structures and right click -> "Show Graph" (Hotkey "G").
3. Plugin creates a graph of all structures that have relationship with selected items.
4. Double clicking on a node recalculates the graph for it.
5. Every node has a hint message that shows C-like typedef.

API
---

**Under construction**

Presentations
=============

* [ZeroNights 2016](https://2016.zeronights.ru/wp-content/uploads/2016/12/zeronights_2016_Kirillov.pptx)
* [Insomni'hack 2018](https://www.youtube.com/watch?v=pnPuwBtW2_4)
* [Infosec in the City 2018](https://www.infosec-city.com/sg18-1-hex-rays) ([Slides](https://1drv.ms/p/s!AocQazyOQ8prgxNCpajrkwURQnPd))

[0]: https://sourceforge.net/projects/classinformer/
[1]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff542043%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
[structure_graph]: Img/structure_builder.JPG
[bad_structures]: Img/bad.JPG
[good_structures]: Img/good.JPG
[builder]: Img/builder.JPG
[virtual_functions]: Img/virtual_functions.JPG
[scanned_variables]: Img/fields_xref.JPG
[classes]: Img/classes.JPG
[feature_history]: https://github.com/igogo-x86/HexRaysPyTools/wiki/History
