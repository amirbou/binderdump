
package com.android.intentresolver;

import com.android.intentresolver.IChooserController;

interface IChooserInteractiveSessionCallback {
    oneway void registerChooserController(in IChooserController updater);
    oneway void onDrawerVerticalOffsetChanged(in int offset);
}
