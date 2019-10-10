<!DOCTYPE HTML>
<html>
  <head>
    <title>Lab RADIUS Server</title>
    <script src="script.js"></script>	
    <link rel="stylesheet" type="text/css" href="style.css">
  </head>
  <body spellcheck="false">
    <form name="userForm" style="text-align: center;" onsubmit="return getUser(this)">
      <input type="text" name="inUser" placeholder="Enter Username" class="long" autofocus>
      <br>
      <input type="submit" name="click" value="click me">
    </form>
    <form name="avpForm" class="bordered" style="display: none;" onsubmit="return setUser(this)">
      <table>
        <tr>
          <th id="userName" align="left"></th>
          <th align="right">
            <label onclick="closeAndInit(this.form)"> &#10006 </label>
          </th>
        </tr>
        <?php
          $items = json_decode(file_get_contents("scheme.json"));
          foreach($items as $list => $avps) {
            echo '<tr><td colspan="2" align="center"><em>';
            echo $list . ' items</em></td></tr>' . "\n";
            foreach($avps as $attr => $info) {
              echo '<tr> <td title="' . $info . '"> ' . $attr;
              echo ': </td> <td> <input type="text" id="';
              echo $attr . '" class="' . $list .'"> </td> </tr>' . "\n";
            }
          } 
        ?>
        <tr style="text-align: center;">
          <td> 
            <input name="click" type="submit" value="Save">
          </td>
          <td> 
            <input type="button" value="Close" onclick="closeAndInit(this.form)">
          </td>
        </tr>
      </table> 
    </form>
 </body>
</html>
