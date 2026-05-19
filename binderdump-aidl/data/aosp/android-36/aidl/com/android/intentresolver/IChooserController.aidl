
package com.android.intentresolver;

import android.content.Intent;

interface IChooserController {
    oneway void updateIntent(in Intent intent);
}
