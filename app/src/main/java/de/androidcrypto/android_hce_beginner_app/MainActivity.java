package de.androidcrypto.android_hce_beginner_app;

import android.content.Intent;
import android.os.Bundle;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.navigation.NavigationBarView;

import de.androidcrypto.android_hce_beginner_app.homekey.HomeKeyActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);

        BottomNavigationView bottomNav = findViewById(R.id.bottom_navigation);
        bottomNav.setOnItemSelectedListener(navListener);

        getSupportFragmentManager()
                .beginTransaction()
                .replace(R.id.fragment_container, new HomeFragment())
                .commit();
    }

    private final NavigationBarView.OnItemSelectedListener navListener = item -> {
        int id = item.getItemId();

        if (id == R.id.homekey) {
            // HomeKey is an Activity, not a fragment — launch it directly
            startActivity(new Intent(this, HomeKeyActivity.class));
            // Return false so the bottom nav doesn't visually select this tab
            // (the user will be taken to a new screen and come back via back press)
            return false;
        }

        Fragment selected = null;
        if      (id == R.id.home)  selected = new HomeFragment();
        else if (id == R.id.read)  selected = new ReadFragment();
        else if (id == R.id.write) selected = new WriteFragment();

        if (selected != null) {
            getSupportFragmentManager()
                    .beginTransaction()
                    .replace(R.id.fragment_container, selected)
                    .commit();
            return true;
        }
        return false;
    };
}
