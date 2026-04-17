package com.encryptvault.routinetracker

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.time.LocalDate

data class RoutineItem(
    val title: String,
    val createdAt: String = LocalDate.now().toString(),
    var completedForDate: String? = null
)

@Composable
fun RoutineTrackerApp() {
    val context = LocalContext.current
    val sharedPreferences = remember {
        context.getSharedPreferences("routine_tracker", Context.MODE_PRIVATE)
    }
    val gson = remember { Gson() }

    val routines = remember {
        mutableStateListOf<RoutineItem>().apply {
            addAll(loadItems(sharedPreferences, gson))
        }
    }

    var newRoutineTitle by remember { mutableStateOf("") }
    val today = LocalDate.now().toString()
    val completedCount = routines.count { it.completedForDate == today }
    val progress = if (routines.isEmpty()) 0f else completedCount.toFloat() / routines.size.toFloat()

    MaterialTheme {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "Daily Routine Tracker",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )
            Text(text = "Date: $today")
            Text(text = "Progress: $completedCount/${routines.size}")
            LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                OutlinedTextField(
                    value = newRoutineTitle,
                    onValueChange = { newRoutineTitle = it },
                    modifier = Modifier.weight(1f),
                    label = { Text("Add a routine") },
                    singleLine = true
                )
                Button(
                    onClick = {
                        val title = newRoutineTitle.trim()
                        if (title.isNotEmpty()) {
                            routines.add(RoutineItem(title = title))
                            saveItems(sharedPreferences, gson, routines)
                            newRoutineTitle = ""
                        }
                    },
                    modifier = Modifier.align(Alignment.CenterVertically)
                ) {
                    Text("Add")
                }
            }

            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                itemsIndexed(routines) { index, item ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(text = item.title, style = MaterialTheme.typography.titleMedium)
                                Text(
                                    text = if (item.completedForDate == today) "Done today ✅" else "Pending",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                            Checkbox(
                                checked = item.completedForDate == today,
                                onCheckedChange = { checked ->
                                    routines[index] = item.copy(completedForDate = if (checked) today else null)
                                    saveItems(sharedPreferences, gson, routines)
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun saveItems(sharedPreferences: android.content.SharedPreferences, gson: Gson, items: List<RoutineItem>) {
    sharedPreferences.edit().putString("routines", gson.toJson(items)).apply()
}

private fun loadItems(sharedPreferences: android.content.SharedPreferences, gson: Gson): List<RoutineItem> {
    val raw = sharedPreferences.getString("routines", null) ?: return emptyList()
    val type = object : TypeToken<List<RoutineItem>>() {}.type
    return runCatching { gson.fromJson<List<RoutineItem>>(raw, type) }.getOrDefault(emptyList())
}
